import nodemailer from 'nodemailer';

const ENV = process.env;

function readSmtpConfig() {
  return {
    host: ENV.SMTP_HOST,
    port: Number(ENV.SMTP_PORT || 587),
    secure: String(ENV.SMTP_SECURE || 'false').toLowerCase() === 'true',
    user: ENV.SMTP_USER,
    pass: ENV.SMTP_PASSWORD,
    from: ENV.SMTP_FROM,
  };
}

export function isMailConfigured() {
  const c = readSmtpConfig();
  return Boolean(c.host && c.user && c.pass && c.from);
}

let _transporter = null;
function transporter() {
  if (_transporter) return _transporter;
  const c = readSmtpConfig();
  if (!isMailConfigured()) {
    throw new Error('Mail delivery is not configured. Set SMTP_* env vars.');
  }
  _transporter = nodemailer.createTransport({
    host: c.host,
    port: c.port,
    secure: c.secure,
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
    auth: { user: c.user, pass: c.pass },
  });
  return _transporter;
}

function fromAddress() {
  return readSmtpConfig().from;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

export async function sendRecoveryLink({ email, link, hint }) {
  const safeHint = hint ? escapeHtml(hint) : '';
  const subject = 'Your Web3Keys recovery link';
  const text =
    `Someone (hopefully you) asked to recover their Web3Keys identity.\n\n` +
    `Open this link to download your encrypted backup:\n${link}\n\n` +
    `This link expires in 15 minutes and can be used once.\n` +
    `Your recovery passphrase is still required to decrypt the backup, so the link alone is not enough to access your identity.\n\n` +
    (hint ? `Backup for: ${hint}\n\n` : '') +
    `If you didn't request this, ignore this email — the encrypted backup is useless without your passphrase.`;

  const html = `<div style="font-family: -apple-system, system-ui, Inter, Arial, sans-serif; line-height: 1.5; color: #1a1f2c; max-width: 540px;">
    <h2 style="margin-top: 0;">Recover your Web3Keys identity</h2>
    <p>Someone (hopefully you) asked to recover their Web3Keys identity. Open the link below within the next 15 minutes to download your encrypted backup. You'll need your recovery passphrase to decrypt it.</p>
    <p style="margin: 24px 0;">
      <a href="${escapeHtml(link)}" style="background: #00e5ff; color: #0a0c10; padding: 12px 18px; border-radius: 10px; text-decoration: none; font-weight: 600; display: inline-block;">Open recovery link</a>
    </p>
    <p style="font-size: 13px; color: #5c6473;">Or paste this URL into your browser:<br>
      <a href="${escapeHtml(link)}" style="color: #2557ff; word-break: break-all;">${escapeHtml(link)}</a>
    </p>
    ${safeHint ? `<p style="font-size: 13px; color: #5c6473;">Backup for: <strong>${safeHint}</strong></p>` : ''}
    <hr style="border: 0; border-top: 1px solid #e5e8ef; margin: 24px 0;">
    <p style="font-size: 12px; color: #5c6473;">If you didn't request this, you can ignore it. Your encrypted backup is useless without your passphrase.</p>
    <p style="font-size: 12px; color: #5c6473;">— Web3Keys</p>
  </div>`;

  const info = await transporter().sendMail({
    from: fromAddress(),
    to: email,
    subject,
    text,
    html,
  });
  return { provider: 'smtp', messageId: info.messageId };
}
