create table if not exists public.profiles (
    id uuid primary key references auth.users (id) on delete cascade,
    username text not null,
    created_at timestamptz not null default now()
);

create unique index if not exists profiles_username_lower_key
    on public.profiles (lower(username));

alter table public.profiles enable row level security;

create or replace function public.auth_identities(lookup_email text)
returns table (user_id uuid, providers text[])
language sql
security definer
set search_path = ''
as $$
    select u.id, coalesce(array_agg(i.provider)::text[], '{}'::text[])
    from auth.users u
    left join auth.identities i on i.user_id = u.id
    where lower(u.email) = lower(lookup_email)
    group by u.id;
$$;

revoke all on function public.auth_identities(text) from public, anon, authenticated;
grant execute on function public.auth_identities(text) to service_role;
