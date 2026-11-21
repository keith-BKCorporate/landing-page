-- 005: weekly CSV backup of website form data.
-- The Apps Script in 004_email_alerts.gs calls this with a secret token once a week,
-- emails each table as a CSV attachment, and the call itself keeps the free project awake.
-- Only the sha256 of the token is stored here: replace TOKEN_SHA256 in the SQL editor,
-- never commit the real value.

create extension if not exists pgcrypto with schema extensions;

create or replace function public.backup_export(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  if encode(digest(coalesce(p_token, ''), 'sha256'), 'hex') <> 'TOKEN_SHA256' then
    raise exception 'denied';
  end if;
  return jsonb_build_object(
    'contact_submissions', coalesce((select jsonb_agg(t order by t.created_at) from contact_submissions t), '[]'::jsonb),
    'programme_registrations', coalesce((select jsonb_agg(t order by t.created_at) from programme_registrations t), '[]'::jsonb),
    'newsletter_subscribers', coalesce((select jsonb_agg(t order by t.created_at) from newsletter_subscribers t), '[]'::jsonb)
  );
end $$;

revoke all on function public.backup_export(text) from public;
grant execute on function public.backup_export(text) to anon;
