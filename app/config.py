import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

_REQUIRED = (
    "SUPABASE_URL",
    "SUPABASE_ANON_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "SESSION_SECRET",
)


@dataclass(frozen=True)
class Settings:
    supabase_url: str
    supabase_anon_key: str
    supabase_service_role_key: str
    session_secret: str
    site_url: str
    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str


def load_settings() -> Settings:
    missing = [name for name in _REQUIRED if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            "Missing environment variables: "
            + ", ".join(missing)
            + ". Copy .env.example to .env, fill it in, and restart the server."
        )
    return Settings(
        supabase_url=os.environ["SUPABASE_URL"],
        supabase_anon_key=os.environ["SUPABASE_ANON_KEY"],
        supabase_service_role_key=os.environ["SUPABASE_SERVICE_ROLE_KEY"],
        session_secret=os.environ["SESSION_SECRET"],
        site_url=os.environ.get("SITE_URL", "http://localhost:8000"),
        google_client_id=os.environ.get("GOOGLE_CLIENT_ID", ""),
        google_client_secret=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
        google_redirect_uri=os.environ.get(
            "GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback"
        ),
    )


settings = load_settings()
