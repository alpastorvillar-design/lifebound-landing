const ALLOWED_ORIGINS = [
  'https://lifebound.io',
  'https://www.lifebound.io',
  'https://lifebound-landing.vercel.app'
];
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL_LENGTH = 254; // RFC 5321 limit
const MAX_BODY_SIZE = 512;    // bytes, more than enough for an email field

// Rate limiting: max 3 requests per IP per 24 hours
const RATE_LIMIT = 3;
const RATE_WINDOW_MS = 24 * 60 * 60 * 1000;
const ipRequests = new Map();

function getRateLimitInfo(ip) {
  const now = Date.now();
  const entry = ipRequests.get(ip);

  if (!entry) {
    ipRequests.set(ip, { count: 1, firstRequest: now });
    return { allowed: true };
  }

  if (now - entry.firstRequest > RATE_WINDOW_MS) {
    ipRequests.set(ip, { count: 1, firstRequest: now });
    return { allowed: true };
  }

  if (entry.count >= RATE_LIMIT) {
    return { allowed: false };
  }

  entry.count += 1;
  return { allowed: true };
}

function setSecurityHeaders(res, origin) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

module.exports = async function handler(req, res) {

  // 1. CORS — check origin before anything else
  const origin = req.headers.origin || '';
  if (!ALLOWED_ORIGINS.includes(origin)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  // 2. Handle CORS preflight (OPTIONS)
  if (req.method === 'OPTIONS') {
    setSecurityHeaders(res, origin);
    return res.status(204).end();
  }

  // 3. Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  setSecurityHeaders(res, origin);

  // 4. Validate Content-Type
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/json')) {
    return res.status(415).json({ error: 'Unsupported media type' });
  }

  // 5. Check API key is configured
  if (!process.env.BREVO_API_KEY) {
    return res.status(500).json({ error: 'Service unavailable' });
  }

  // 6. Rate limiting by IP
  const ip =
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'unknown';

  const { allowed } = getRateLimitInfo(ip);
  if (!allowed) {
    return res.status(429).json({ error: 'Too many requests. Try again later.' });
  }

  // 7. Validate body exists
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ error: 'Invalid request' });
  }

  // 8. Check body size
  const bodySize = JSON.stringify(req.body).length;
  if (bodySize > MAX_BODY_SIZE) {
    return res.status(413).json({ error: 'Request too large' });
  }

  const { email } = req.body;

  // 9. Validate and sanitize email
  if (
    !email ||
    typeof email !== 'string' ||
    email.length > MAX_EMAIL_LENGTH ||
    !EMAIL_REGEX.test(email.trim())
  ) {
    return res.status(400).json({ error: 'Invalid email' });
  }

  const sanitizedEmail = email.trim().toLowerCase();

  try {
    const response = await fetch('https://api.brevo.com/v3/contacts', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': process.env.BREVO_API_KEY
      },
      body: JSON.stringify({
        email: sanitizedEmail,
        listIds: [3],
        updateEnabled: true
      })
    });

    if (!response.ok && response.status !== 204) {
      throw new Error('Upstream error');
    }

    return res.status(200).json({ success: true });
  } catch (err) {
    // Never expose internal error details
    return res.status(500).json({ error: 'Failed to subscribe. Please try again.' });
  }
};
