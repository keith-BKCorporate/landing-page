-- 007: newsletter and programme registration forms also insert only via the Netlify function
-- contact-enquiry (form = 'newsletter' / 'registration'), which runs the spam checks and uses
-- the service-role key. Remove the public (anon) insert rules so bots cannot skip the checks.
--
-- Undo:
--   create policy "Anyone can subscribe" on newsletter_subscribers for insert to anon, authenticated with check (consent = true);
--   create policy "Anonymous can register" on programme_registrations for insert to anon, authenticated with check (consent_pdpa = true);

drop policy if exists "Anyone can subscribe" on newsletter_subscribers;
drop policy if exists "Anonymous can register" on programme_registrations;
