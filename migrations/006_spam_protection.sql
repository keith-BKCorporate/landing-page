-- 006: close the direct-insert back door on contact_submissions.
--
-- The contact form posts to /.netlify/functions/contact-enquiry, which runs the spam checks
-- and inserts with SUPABASE_SERVICE_ROLE_KEY (Netlify env, never in the repo or browser).
-- The service role bypasses RLS, so the public (anon) insert rule is no longer needed.
--
-- Run only after GET /.netlify/functions/contact-enquiry returns "mode":"service".
-- Undo: create policy "Allow anonymous inserts" on contact_submissions for insert to anon with check (true);

drop policy if exists "Allow anonymous inserts" on contact_submissions;

comment on table contact_submissions is
  'Website enquiries. Inserted only by the Netlify function contact-enquiry (service role).';
