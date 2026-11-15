// Google Apps Script mailer for 004_email_alerts.sql.
// Deploy at script.google.com, signed in as keith@bkcorporate.com:
//   Deploy > New deployment > Web app, Execute as: Me, Who has access: Anyone.
// Replace TOKEN with a long random string (keep it out of this public repo) and use the
// same value in the trigger URL. Supabase posts {table, record} on every new row.

const TOKEN = 'REPLACE_WITH_SECRET';
const TO = 'keith@bkcorporate.com';
const LABEL = {
  contact_submissions: 'New website enquiry',
  programme_registrations: 'New seminar registration',
  newsletter_subscribers: 'New newsletter subscriber'
};

function doPost(e) {
  if (!e || !e.parameter || e.parameter.token !== TOKEN) return ContentService.createTextOutput('denied');
  const p = JSON.parse(e.postData.contents);
  const r = p.record || {};
  const who = r.name || r.email || '';
  const body = Object.keys(r)
    .filter(k => r[k] !== null && r[k] !== '' && k !== 'id')
    .map(k => k + ': ' + r[k]).join('\n');
  const mail = {
    to: TO,
    subject: (LABEL[p.table] || 'New row in ' + p.table) + (who ? ': ' + who : ''),
    body: body + '\n\nAll records: https://supabase.com/dashboard/project/uloodavzquardkeecrlx/editor'
  };
  if (r.email) mail.replyTo = r.email;
  MailApp.sendEmail(mail);
  return ContentService.createTextOutput('ok');
}
