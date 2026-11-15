-- 004: email keith@bkcorporate.com when a website form saves a row.
-- Each insert posts {table, record} to the Apps Script web app in 004_email_alerts.gs.
-- The real URL carries a secret token: replace ALERT_URL below in the SQL editor only,
-- never commit it. The post is asynchronous (pg_net), so a mail failure never blocks a form.

create extension if not exists pg_net with schema extensions;

create or replace function public.notify_new_row() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform net.http_post(
    url := 'ALERT_URL',
    body := jsonb_build_object('table', TG_TABLE_NAME, 'record', to_jsonb(NEW)),
    headers := '{"Content-Type": "application/json"}'::jsonb
  );
  return NEW;
end $$;

drop trigger if exists alert_contact on contact_submissions;
create trigger alert_contact after insert on contact_submissions
  for each row execute function public.notify_new_row();

drop trigger if exists alert_registration on programme_registrations;
create trigger alert_registration after insert on programme_registrations
  for each row execute function public.notify_new_row();

drop trigger if exists alert_newsletter on newsletter_subscribers;
create trigger alert_newsletter after insert on newsletter_subscribers
  for each row execute function public.notify_new_row();
