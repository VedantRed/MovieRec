import re
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .supabase_client import admin_client, auth_client

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

templates = Jinja2Templates(directory=BASE_DIR / "templates")

ALLOWED_OTP_TYPES = {"signup", "email", "magiclink", "recovery", "invite", "email_change"}
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")


def render_error(request: Request, template: str, message: str, status_code: int = 200):
    return templates.TemplateResponse(
        request, template, {"error": message}, status_code=status_code
    )


@app.get("/")
def home(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "username": request.session.get("username"),
            "email": request.session.get("email"),
        },
    )


@app.get("/signup")
def signup_page(request: Request):
    return templates.TemplateResponse(request, "signup.html", {})


@app.post("/signup")
def signup(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        return render_error(request, "signup.html", "Enter a valid email address.", 400)
    if len(password) < 8:
        return render_error(request, "signup.html", "Password must be at least 8 characters.", 400)

    try:
        auth_client.auth.sign_up({"email": email, "password": password})
    except Exception:
        return render_error(
            request,
            "signup.html",
            "We couldn't create that account. It may already exist, or the email may be invalid.",
            400,
        )

    return templates.TemplateResponse(request, "check_email.html", {"email": email})


@app.get("/auth/confirm")
def confirm_email(request: Request, token_hash: str = "", type: str = "signup"):
    if type not in ALLOWED_OTP_TYPES:
        return render_error(request, "confirm_error.html", "This link is not valid.", 400)

    try:
        result = auth_client.auth.verify_otp({"token_hash": token_hash, "type": type})
    except Exception:
        return render_error(
            request,
            "confirm_error.html",
            "This confirmation link is invalid or has expired. Sign up again to get a new one.",
            400,
        )

    user = getattr(result, "user", None)
    if user is None:
        return render_error(request, "confirm_error.html", "This link is no longer valid.", 400)

    request.session.clear()
    request.session["user_id"] = user.id
    request.session["email"] = user.email
    return RedirectResponse("/choose-username", status_code=303)


@app.get("/choose-username")
def choose_username_page(request: Request):
    if not request.session.get("user_id"):
        return RedirectResponse("/signup", status_code=303)
    return templates.TemplateResponse(request, "choose_username.html", {})


@app.post("/choose-username")
def choose_username(request: Request, username: str = Form(...)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/signup", status_code=303)

    username = username.strip()
    if not USERNAME_PATTERN.match(username):
        return render_error(
            request,
            "choose_username.html",
            "Usernames need 3-20 letters, numbers, or underscores.",
            400,
        )

    try:
        taken = (
            admin_client.table("profiles")
            .select("id")
            .ilike("username", username)
            .limit(1)
            .execute()
        )
        if taken.data:
            return render_error(request, "choose_username.html", "That username is already taken.", 400)

        admin_client.table("profiles").insert(
            {"id": user_id, "username": username}
        ).execute()
    except Exception:
        return render_error(
            request,
            "choose_username.html",
            "We couldn't save that username. Try a different one.",
            400,
        )

    request.session["username"] = username
    return RedirectResponse("/", status_code=303)


@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    invalid = "Invalid login."

    try:
        profile = (
            admin_client.table("profiles")
            .select("id, username")
            .ilike("username", username.strip())
            .limit(1)
            .execute()
        )
    except Exception:
        return render_error(
            request,
            "login.html",
            "Login is temporarily unavailable. Try again shortly.",
            503,
        )
    if not profile.data:
        return render_error(request, "login.html", invalid, 401)

    user_id = profile.data[0]["id"]
    stored_username = profile.data[0]["username"]

    try:
        email = admin_client.auth.admin.get_user_by_id(user_id).user.email
    except Exception:
        return render_error(request, "login.html", invalid, 401)

    if not email:
        return render_error(request, "login.html", invalid, 401)

    try:
        auth_client.auth.sign_in_with_password({"email": email, "password": password})
    except Exception:
        return render_error(request, "login.html", invalid, 401)

    request.session.clear()
    request.session["user_id"] = user_id
    request.session["email"] = email
    request.session["username"] = stored_username
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
