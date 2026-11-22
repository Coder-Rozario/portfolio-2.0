require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const http = require('http');
const https = require('https');

const app = express();

// ==================== CONSTANTS ====================
const OWNER_NAME = process.env.OWNER_NAME || 'Shuvro Rozario';
const WAIT_FOR_EMAIL = process.env.WAIT_FOR_EMAIL === 'true'; // default: respond instantly

// Render (and most hosts) sit behind a proxy. Needed for correct client IP + rate limiting.
app.set('trust proxy', 1);

function escapeHTML(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, function (match) {
    const chars = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return chars[match];
  });
}

// ==================== SECURITY MIDDLEWARE ====================
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false
}));

// ==================== CORS CONFIGURATION ====================
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      process.env.FRONTEND_URL,
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      'http://localhost:5174',
      'http://127.0.0.1:5174',
      'https://shuvo-rozario.netlify.app'
    ];

    const isLocalhost = !!origin && /^http:\/\/localhost(:\d+)?$/.test(origin);
    const isLoopback = !!origin && /^http:\/\/127\.0\.0\.1(:\d+)?$/.test(origin);

    if (!origin || allowedOrigins.includes(origin) || isLocalhost || isLoopback) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
}));

// Handle preflight requests
app.options('*', cors());

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// ==================== HEALTH CHECK ENDPOINT ====================
// Declared BEFORE the rate limiter so uptime pings never count against the limit.
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    message: 'Portfolio server is running smoothly'
  });
});

// ==================== RATE LIMITING ====================
// Prevent brute force / abuse on contact endpoint
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests from this IP, please try again later.' }
});
app.use(limiter);

// ==================== BREVO SMTP CONFIGURATION ====================
// NOTE: Render free web services block outbound SMTP ports 25, 465 and 587.
// Brevo also supports port 2525, which works on Render. Override with SMTP_PORT if needed.
const SMTP_PORT = parseInt(process.env.SMTP_PORT, 10) || 2525;

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp-relay.brevo.com',
  port: SMTP_PORT,
  secure: false, // STARTTLS is used automatically on non-SSL ports
  pool: true,
  maxConnections: 2,
  maxMessages: Infinity,
  connectionTimeout: 15000,
  greetingTimeout: 15000,
  socketTimeout: 20000,
  auth: {
    user: process.env.EMAIL_USER, // Brevo SMTP login e.g. xxxx@smtp-brevo.com
    pass: process.env.EMAIL_PASS, // Brevo SMTP key
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Test email configuration on startup (non-blocking)
transporter.verify(function (error) {
  if (error) {
    console.log('[EMAIL] Configuration error:', error.message);
  } else {
    console.log(`[EMAIL] Brevo SMTP server is ready (port ${SMTP_PORT})`);
  }
});

// ==================== EMAIL TEMPLATES ====================
// Table-based layout with inline styles for maximum email client compatibility.
const BRAND = {
  primary: '#6d28d9',
  primaryDark: '#4c1d95',
  navy: '#0f0a2e',
  text: '#1f2937',
  muted: '#6b7280',
  border: '#e5e7eb',
  bg: '#f3f4f6',
  card: '#ffffff',
  soft: '#f9fafb'
};

const FONT = "'Segoe UI', Roboto, Helvetica, Arial, sans-serif";

function formatDateTime(date) {
  try {
    return date.toLocaleString('en-GB', {
      dateStyle: 'medium',
      timeStyle: 'short',
      timeZone: 'Asia/Dhaka'
    }) + ' (BST)';
  } catch {
    return date.toISOString();
  }
}

function infoRow(label, valueHtml, isLast) {
  return `
    <tr>
      <td style="padding: 14px 0; ${isLast ? '' : `border-bottom: 1px solid ${BRAND.border};`} width: 90px; vertical-align: top; font-family: ${FONT}; font-size: 11px; font-weight: 700; letter-spacing: 1.2px; text-transform: uppercase; color: ${BRAND.muted};">
        ${label}
      </td>
      <td style="padding: 14px 0; ${isLast ? '' : `border-bottom: 1px solid ${BRAND.border};`} vertical-align: top; font-family: ${FONT}; font-size: 15px; color: ${BRAND.text};">
        ${valueHtml}
      </td>
    </tr>`;
}

function buildOwnerEmail({ safeName, safeNumber, safeEmail, safeMessage }) {
  const messageHtml = safeMessage.replace(/\r?\n/g, '<br>');
  const receivedAt = formatDateTime(new Date());

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="x-apple-disable-message-reformatting">
  <title>New Portfolio Message</title>
</head>
<body style="margin: 0; padding: 0; background-color: ${BRAND.bg};">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: ${BRAND.bg}; padding: 32px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width: 620px; background-color: ${BRAND.card}; border-radius: 14px; overflow: hidden; border: 1px solid ${BRAND.border};">

          <!-- Accent bar -->
          <tr>
            <td style="height: 5px; background-color: ${BRAND.primary}; background-image: linear-gradient(90deg, ${BRAND.primaryDark}, ${BRAND.primary}, #8b5cf6); font-size: 0; line-height: 0;">&nbsp;</td>
          </tr>

          <!-- Header -->
          <tr>
            <td style="background-color: ${BRAND.navy}; padding: 36px 36px 32px 36px;">
              <p style="margin: 0 0 10px 0; font-family: ${FONT}; font-size: 11px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: #a78bfa;">
                Portfolio Inbox
              </p>
              <h1 style="margin: 0 0 8px 0; font-family: ${FONT}; font-size: 26px; line-height: 1.3; font-weight: 700; color: #ffffff;">
                New message from ${safeName}
              </h1>
              <p style="margin: 0; font-family: ${FONT}; font-size: 14px; line-height: 1.6; color: #c4b5fd;">
                Someone reached out through your portfolio website.
              </p>
            </td>
          </tr>

          <!-- Contact details -->
          <tr>
            <td style="padding: 32px 36px 8px 36px;">
              <p style="margin: 0 0 6px 0; font-family: ${FONT}; font-size: 13px; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; color: ${BRAND.primary};">
                Contact Details
              </p>
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                ${infoRow('Name', `<strong>${safeName}</strong>`, false)}
                ${infoRow('Email', `<a href="mailto:${safeEmail}" style="color: ${BRAND.primary}; text-decoration: none; font-weight: 600;">${safeEmail}</a>`, false)}
                ${infoRow('Phone', `<a href="tel:${safeNumber}" style="color: ${BRAND.primary}; text-decoration: none; font-weight: 600;">${safeNumber}</a>`, false)}
                ${infoRow('Received', receivedAt, true)}
              </table>
            </td>
          </tr>

          <!-- Message -->
          <tr>
            <td style="padding: 24px 36px 8px 36px;">
              <p style="margin: 0 0 12px 0; font-family: ${FONT}; font-size: 13px; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; color: ${BRAND.primary};">
                Message
              </p>
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="background-color: ${BRAND.soft}; border: 1px solid ${BRAND.border}; border-left: 4px solid ${BRAND.primary}; border-radius: 8px; padding: 20px 22px; font-family: ${FONT}; font-size: 15px; line-height: 1.75; color: ${BRAND.text};">
                    ${messageHtml}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CTA -->
          <tr>
            <td align="left" style="padding: 24px 36px 36px 36px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="background-color: ${BRAND.primary}; border-radius: 8px;">
                    <a href="mailto:${safeEmail}" style="display: inline-block; padding: 13px 26px; font-family: ${FONT}; font-size: 14px; font-weight: 700; color: #ffffff; text-decoration: none; letter-spacing: 0.3px;">
                      Reply to ${safeName} &rarr;
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: ${BRAND.soft}; border-top: 1px solid ${BRAND.border}; padding: 20px 36px; text-align: center;">
              <p style="margin: 0; font-family: ${FONT}; font-size: 12px; line-height: 1.6; color: ${BRAND.muted};">
                This message was sent from the contact form on your portfolio website.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

function buildUserConfirmationEmail({ safeName }) {
  const year = new Date().getFullYear();

  const step = (num, title, desc, isLast) => `
    <tr>
      <td style="padding: 0 0 ${isLast ? '0' : '18px'} 0;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
          <tr>
            <td width="36" valign="top">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td align="center" valign="middle" width="28" height="28" style="width: 28px; height: 28px; background-color: ${BRAND.primary}; border-radius: 14px; font-family: ${FONT}; font-size: 13px; font-weight: 700; color: #ffffff; text-align: center;">
                    ${num}
                  </td>
                </tr>
              </table>
            </td>
            <td valign="top" style="font-family: ${FONT};">
              <p style="margin: 0 0 3px 0; font-size: 15px; font-weight: 700; color: ${BRAND.text};">${title}</p>
              <p style="margin: 0; font-size: 14px; line-height: 1.6; color: ${BRAND.muted};">${desc}</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>`;

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="x-apple-disable-message-reformatting">
  <title>Thank You for Reaching Out</title>
</head>
<body style="margin: 0; padding: 0; background-color: ${BRAND.bg};">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: ${BRAND.bg}; padding: 32px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width: 620px; background-color: ${BRAND.card}; border-radius: 14px; overflow: hidden; border: 1px solid ${BRAND.border};">

          <!-- Accent bar -->
          <tr>
            <td style="height: 5px; background-color: ${BRAND.primary}; background-image: linear-gradient(90deg, ${BRAND.primaryDark}, ${BRAND.primary}, #8b5cf6); font-size: 0; line-height: 0;">&nbsp;</td>
          </tr>

          <!-- Header -->
          <tr>
            <td style="background-color: ${BRAND.navy}; padding: 44px 36px 38px 36px; text-align: center;">
              <p style="margin: 0 0 12px 0; font-family: ${FONT}; font-size: 11px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: #a78bfa;">
                ${escapeHTML(OWNER_NAME)}
              </p>
              <h1 style="margin: 0 0 10px 0; font-family: ${FONT}; font-size: 28px; line-height: 1.3; font-weight: 700; color: #ffffff;">
                Thank you, ${safeName}
              </h1>
              <p style="margin: 0; font-family: ${FONT}; font-size: 15px; line-height: 1.6; color: #c4b5fd;">
                Your message has been received successfully.
              </p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding: 36px 36px 8px 36px;">
              <p style="margin: 0 0 14px 0; font-family: ${FONT}; font-size: 16px; line-height: 1.7; color: ${BRAND.text};">
                Hi ${safeName},
              </p>
              <p style="margin: 0; font-family: ${FONT}; font-size: 15px; line-height: 1.75; color: ${BRAND.muted};">
                Thank you for taking the time to get in touch through my portfolio website. I truly appreciate your interest, and I will read your message carefully.
              </p>
            </td>
          </tr>

          <!-- What happens next -->
          <tr>
            <td style="padding: 24px 36px 8px 36px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: ${BRAND.soft}; border: 1px solid ${BRAND.border}; border-radius: 10px;">
                <tr>
                  <td style="padding: 26px 26px 26px 26px;">
                    <p style="margin: 0 0 20px 0; font-family: ${FONT}; font-size: 13px; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; color: ${BRAND.primary};">
                      What happens next
                    </p>
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                      ${step('1', 'Review', 'I will go through your message and understand your requirements.', false)}
                      ${step('2', 'Response', 'You will receive a reply from me within 24 hours.', true)}
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Sign-off -->
          <tr>
            <td style="padding: 28px 36px 40px 36px;">
              <p style="margin: 0 0 4px 0; font-family: ${FONT}; font-size: 15px; line-height: 1.6; color: ${BRAND.muted};">
                Best regards,
              </p>
              <p style="margin: 0; font-family: ${FONT}; font-size: 17px; font-weight: 700; color: ${BRAND.text};">
                ${escapeHTML(OWNER_NAME)}
              </p>
              <p style="margin: 2px 0 0 0; font-family: ${FONT}; font-size: 13px; color: ${BRAND.primary}; font-weight: 600;">
                Full Stack Web Developer
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: ${BRAND.navy}; padding: 22px 36px; text-align: center;">
              <p style="margin: 0 0 4px 0; font-family: ${FONT}; font-size: 12px; color: #c4b5fd;">
                &copy; ${year} ${escapeHTML(OWNER_NAME)}. All rights reserved.
              </p>
              <p style="margin: 0; font-family: ${FONT}; font-size: 11px; color: #8b7fc7;">
                You are receiving this email because you submitted the contact form on my portfolio.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ==================== CONTACT LOGIC FUNCTION ====================
const handleContactForm = async (req, res) => {
  try {
    const { name, number, email, message } = req.body || {};
    console.log('[CONTACT] Submission received');

    // Enhanced validation
    if (!name || !number || !email || !message) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    if (String(name).trim().length < 2) {
      return res.status(400).json({ success: false, message: 'Name must be at least 2 characters long' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(String(email).trim())) {
      return res.status(400).json({ success: false, message: 'Please provide a valid email address' });
    }

    if (String(number).trim().length < 10) {
      return res.status(400).json({ success: false, message: 'Please provide a valid phone number' });
    }

    if (String(message).trim().length < 10) {
      return res.status(400).json({ success: false, message: 'Message must be at least 10 characters long' });
    }

    if (String(message).trim().length > 1000) {
      return res.status(400).json({ success: false, message: 'Message must be less than 1000 characters' });
    }

    // XSS Protection
    const safeName = escapeHTML(String(name).trim());
    const safeNumber = escapeHTML(String(number).trim());
    const safeEmail = escapeHTML(String(email).trim());
    const safeMessage = escapeHTML(String(message).trim());

    // IMPORTANT: EMAIL_FROM must be a verified Sender in your Brevo account.
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: process.env.EMAIL_TO,
      replyTo: String(email).trim(),
      subject: `New Portfolio Message from ${safeName}`,
      html: buildOwnerEmail({ safeName, safeNumber, safeEmail, safeMessage })
    };

    const userConfirmationMail = {
      from: process.env.EMAIL_FROM,
      to: String(email).trim(),
      subject: `Thank you for contacting ${OWNER_NAME}`,
      html: buildUserConfirmationEmail({ safeName })
    };

    // Deliver both emails concurrently
    const sendEmails = Promise.allSettled([
      transporter.sendMail(mailOptions),
      transporter.sendMail(userConfirmationMail)
    ]).then((results) => {
      console.log(`[EMAIL] Delivery status for ${safeName}:`, results.map(r => r.status));
      results.forEach((r, i) => {
        if (r.status === 'rejected') {
          console.error(`[EMAIL] ${i === 0 ? 'Owner' : 'User'} mail failed:`, r.reason && r.reason.message);
        }
      });
      return results;
    });

    if (WAIT_FOR_EMAIL) {
      // Slower, but the client only gets success if at least one email was delivered
      const results = await sendEmails;
      if (results[0].status === 'rejected' && results[1].status === 'rejected') {
        throw new Error('Email dispatch failed entirely.');
      }
    }
    // Otherwise: respond immediately, emails continue in the background

    return res.status(200).json({
      success: true,
      message: 'Message received! A confirmation email will arrive shortly.'
    });

  } catch (error) {
    console.error('[CONTACT] Contact form error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to send message. Please try again later.'
    });
  }
};

app.post('/api/messages', handleContactForm);
app.post('/api/contact', handleContactForm);

// ==================== ADDITIONAL PORTFOLIO ENDPOINTS ====================
app.get('/api/projects', (req, res) => {
  const projects = [
    {
      id: 1,
      title: "Yokebud E-commerce",
      description: "Full-stack e-commerce platform with advanced features",
      technologies: ["React", "Node.js", "MySQL", "Cloudinary"],
      category: "Full Stack",
      image: "/projects/yokebud.jpg",
      liveUrl: "https://yokebud.com",
      githubUrl: "https://github.com/yourusername/yokebud"
    },
    {
      id: 2,
      title: "Portfolio Website",
      description: "Responsive portfolio with contact form and email integration",
      technologies: ["React", "Node.js", "Express", "Nodemailer"],
      category: "Full Stack",
      image: "/projects/portfolio.jpg",
      liveUrl: "https://shuvorozario.com",
      githubUrl: "https://github.com/yourusername/portfolio"
    }
  ];
  res.json({ success: true, projects });
});

app.get('/api/skills', (req, res) => {
  const skills = {
    frontend: [
      { name: "React", level: 90 },
      { name: "JavaScript", level: 85 },
      { name: "HTML5", level: 95 },
      { name: "CSS3", level: 90 }
    ],
    backend: [
      { name: "Node.js", level: 88 },
      { name: "Express.js", level: 85 },
      { name: "MySQL", level: 80 },
      { name: "MongoDB", level: 75 }
    ]
  };
  res.json({ success: true, skills });
});

// ==================== ERROR HANDLING ====================
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

app.use('/api/*', (req, res) => {
  res.status(404).json({ success: false, message: 'API endpoint not found' });
});

app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Portfolio Backend Server is running!',
    endpoints: {
      health: '/health',
      contact: '/api/contact & /api/messages',
      projects: '/api/projects',
      skills: '/api/skills'
    },
    timestamp: new Date().toISOString()
  });
});

// ==================== SERVER STARTUP ====================
const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SERVER] Portfolio server running on port ${PORT}`);

  // ---------- KEEP-ALIVE (prevents Render free-tier sleep) ----------
  // Render automatically provides RENDER_EXTERNAL_URL (your public https URL).
  // Pinging the PUBLIC url is what counts as inbound traffic. localhost does not.
  const rawUrl = process.env.KEEP_ALIVE_URL || process.env.RENDER_EXTERNAL_URL;

  if (!rawUrl) {
    console.log('[KEEP-ALIVE] No public URL found (local environment). Self-ping disabled.');
    return;
  }

  const keepAliveUrl = /\/health\/?$/.test(rawUrl)
    ? rawUrl
    : `${rawUrl.replace(/\/$/, '')}/health`;

  const ping = () => {
    try {
      const client = keepAliveUrl.startsWith('https') ? https : http;
      const req = client.get(keepAliveUrl, (res) => {
        console.log(`[KEEP-ALIVE] Ping ${keepAliveUrl} -> ${res.statusCode}`);
        res.resume();
      });
      req.on('error', (err) => console.log('[KEEP-ALIVE] Ping failed:', err.message));
      req.setTimeout(10000, () => req.destroy());
    } catch (err) {
      console.log('[KEEP-ALIVE] Ping error:', err.message);
    }
  };

  // Render sleeps after 15 min of inactivity, so ping every 10 min
  setInterval(ping, 10 * 60 * 1000);
  setTimeout(ping, 5000);
  console.log(`[KEEP-ALIVE] Self-ping enabled every 10 minutes -> ${keepAliveUrl}`);
});

// Prevent random 502 errors behind Render's load balancer
server.keepAliveTimeout = 120 * 1000;
server.headersTimeout = 121 * 1000;
