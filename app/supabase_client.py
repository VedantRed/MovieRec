from supabase import Client, create_client

from .config import settings

auth_client: Client = create_client(
    settings.supabase_url, settings.supabase_anon_key
)

admin_client: Client = create_client(
    settings.supabase_url, settings.supabase_service_role_key
)
