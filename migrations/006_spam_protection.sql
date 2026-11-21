-- 006: spam protection follow-up (OPTIONAL — paste in Supabase SQL editor when ready).
--
-- Website path (already live after the Netlify deploy):
--   contact form -> /.netlify/functions/contact-enquiry -> contact_submissions
-- Bots that POST straight to Supabase with the public anon key can still insert until
-- the steps below are applied. Do NOT run this until a service-role (or other trusted)
-- key is stored in Netlify env and the function uses it.
--
-- Prerequisites before tightening RLS:
--   1. In Netlify site env, set SUPABASE_SERVICE_ROLE_KEY (Dashboard > Project Settings >
--      API > service_role — never expose this in browser JS).
--   2. Update netlify/functions/contact-enquiry.js to Prefer the service role key for
--      inserts (and keep the anon key out of the insert path).
--   3. Redeploy, confirm one genuine submission still works.
--
-- Then run:

-- Drop open anon insert (bots currently abuse this)
-- drop policy if exists "Allow anonymous inserts" on contact_submissions;

-- Recreate insert only for service role / authenticated admin paths if desired.
-- Example (service role bypasses RLS; no anon policy needed once the browser never inserts):
--   -- (no anon insert policy)
--   -- keep admin read/update from 003_admin_only_access.sql

-- Optional: mark obvious spam rows for review (adjust patterns to match what you see)
-- update contact_submissions
-- set status = 'spam_suspect'
-- where status = 'new'
--   and (
--     company ~* '\mLLC\M' and name !~ '\s'
--     or email ~* '@(mailinator|guerrillamail|tempmail|yopmail)\\.'
--   );

-- Optional helper comment for ops:
comment on table contact_submissions is
  'Website enquiries. Prefer inserts via Netlify function contact-enquiry; tighten anon RLS after service-role is wired.';
