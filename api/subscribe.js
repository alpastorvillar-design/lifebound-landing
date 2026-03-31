const ALLOWED_ORIGIN = 'https://lifebound.io';
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL_LENGTH = 254; // RFC 5321 limit

// Rate limiting: max 3 requests per IP per 24 hours
const RATE_LIMIT = 3;
const RATE_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours
const ipRequests = new Map();

function getRateLimitInfo(ip) {
  const now = Date.now();
  const entry = ipRequests.get(ip);

  if (!entry) {
    ipRequests.set(ip, { count: 1, firstRequest: now });
    return { allowed: true };
  }

  // Reset window if 24h have passed
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

export default async function handler(req, res) {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // CORS: only accept requests from lifebound.io
  const origin = req.headers.origin || '';
  if (origin !== ALLOWED_ORIGIN) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);

  // Rate limiting by IP
  const ip =
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'unknown';

  const { allowed } = getRateLimitInfo(ip);
  if (!allowed) {
    return res.status(429).json({ error: 'Too many requests. Try again later.' });
  }

  // Validate body exists
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ error: 'Invalid request' });
  }

  const { email } = req.body;

  // Validate email
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
}
