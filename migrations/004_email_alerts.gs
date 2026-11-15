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

// ---------- weekly CSV backup (migration 005) ----------
// Emails each table as a CSV attachment to TO; the weekly call also keeps the free
// Supabase project from pausing. SB_ANON is the public key already in js/supabase.js.
// BACKUP_TOKEN must match the sha256 stored in backup_export(); keep it out of the repo.
const SB_URL = 'https://uloodavzquardkeecrlx.supabase.co';
const SB_ANON = 'COPY_FROM_js/supabase.js';
const BACKUP_TOKEN = 'REPLACE_WITH_BACKUP_SECRET';

function weeklyBackup() {
  const res = UrlFetchApp.fetch(SB_URL + '/rest/v1/rpc/backup_export', {
    method: 'post', contentType: 'application/json',
    headers: { apikey: SB_ANON, Authorization: 'Bearer ' + SB_ANON },
    payload: JSON.stringify({ p_token: BACKUP_TOKEN })
  });
  const data = JSON.parse(res.getContentText());
  const day = Utilities.formatDate(new Date(), 'Asia/Kuala_Lumpur', 'yyyy-MM-dd');
  const files = Object.keys(data).filter(t => data[t].length).map(t => Utilities.newBlob(toCsv(data[t]), 'text/csv', t + '_' + day + '.csv'));
  const counts = Object.keys(data).map(t => t + ': ' + data[t].length + ' rows').join('\n');
  MailApp.sendEmail({ to: TO, subject: 'Website data backup ' + day, body: 'Weekly backup of the website form tables (CSV attached).\n\n' + counts, attachments: files });
}

function toCsv(rows) {
  if (!rows.length) return '';
  const cols = Object.keys(rows[0]);
  const cell = v => { if (v === null || v === undefined) return ''; const s = typeof v === 'object' ? JSON.stringify(v) : String(v); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  return [cols.join(',')].concat(rows.map(r => cols.map(c => cell(r[c])).join(','))).join('\r\n');
}

// Run once from the editor: schedules weeklyBackup every Monday 8am and runs it now.
function setupWeeklyBackup() {
  ScriptApp.getProjectTriggers().filter(t => t.getHandlerFunction() === 'weeklyBackup').forEach(t => ScriptApp.deleteTrigger(t));
  ScriptApp.newTrigger('weeklyBackup').timeBased().onWeekDay(ScriptApp.WeekDay.MONDAY).atHour(8).inTimezone('Asia/Kuala_Lumpur').create();
  weeklyBackup();
}
