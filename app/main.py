import base64
import hashlib
import json
import re
import secrets
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .supabase_client import admin_client, auth_client

BASE_DIR = Path(__file__).resolve().parent.parent

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

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


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _id_token_email(id_token: str) -> str:
    try:
        payload = id_token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except Exception:
        return ""
    email = claims.get("email")
    return email.strip().lower() if isinstance(email, str) else ""


@app.get("/auth/google/start")
def google_start(request: Request):
    if not settings.google_client_id or not settings.google_client_secret:
        return render_error(
            request, "auth_error.html", "Google login is not configured yet.", 503
        )

    state = secrets.token_urlsafe(32)
    verifier, challenge = _pkce_pair()
    request.session["oauth_state"] = state
    request.session["oauth_verifier"] = verifier

    query = urlencode(
        {
            "client_id": settings.google_client_id,
            "redirect_uri": settings.google_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
    )
    return RedirectResponse(f"{GOOGLE_AUTH_URL}?{query}", status_code=303)


@app.get("/auth/google/callback")
def google_callback(request: Request, code: str = "", state: str = ""):
    expected_state = request.session.pop("oauth_state", "")
    verifier = request.session.pop("oauth_verifier", "")

    if (
        not code
        or not state
        or not expected_state
        or not verifier
        or not secrets.compare_digest(state, expected_state)
    ):
        return render_error(
            request,
            "auth_error.html",
            "This Google login attempt is invalid or expired. Try again.",
            400,
        )

    try:
        token_response = httpx.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": settings.google_redirect_uri,
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
            },
            timeout=10,
        )
        token_response.raise_for_status()
        id_token = token_response.json().get("id_token")
    except Exception:
        return render_error(
            request,
            "auth_error.html",
            "Google login failed while contacting Google. Try again.",
            400,
        )

    if not id_token:
        return render_error(
            request, "auth_error.html", "Google did not return an identity token.", 400
        )

    email = _id_token_email(id_token)
    if not email:
        return render_error(
            request, "auth_error.html", "Google did not return an email address.", 400
        )

    try:
        lookup = admin_client.rpc(
            "auth_identities", {"lookup_email": email}
        ).execute()
    except Exception:
        return render_error(
            request,
            "auth_error.html",
            "Login is temporarily unavailable. Try again shortly.",
            503,
        )

    providers = []
    if lookup.data:
        providers = lookup.data[0].get("providers") or []
    if providers and "google" not in providers:
        return render_error(
            request,
            "auth_error.html",
            "Google login could not be verified. Try again.",
            400,
        )

    try:
        result = auth_client.auth.sign_in_with_id_token(
            {"provider": "google", "token": id_token}
        )
    except Exception:
        return render_error(
            request,
            "auth_error.html",
            "Google login could not be verified. Try again.",
            400,
        )

    user = getattr(result, "user", None)
    if user is None:
        return render_error(
            request, "auth_error.html", "Google login could not be verified.", 400
        )

    request.session.clear()
    request.session["user_id"] = user.id
    request.session["email"] = user.email

    try:
        profile = (
            admin_client.table("profiles")
            .select("username")
            .eq("id", user.id)
            .limit(1)
            .execute()
        )
    except Exception:
        return render_error(
            request,
            "auth_error.html",
            "Login is temporarily unavailable. Try again shortly.",
            503,
        )

    if profile.data:
        request.session["username"] = profile.data[0]["username"]
        return RedirectResponse("/", status_code=303)
    return RedirectResponse("/choose-username", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
