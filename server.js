const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.disable('etag');
app.set('trust proxy', 1); // trust Apache's X-Forwarded-For for real client IPs
const PORT = process.env.PORT || 3000;
const SECRET_TTL = 24 * 60 * 60 * 1000; // 24 hours
const MAX_SECRETS = 10000; // cap total secrets in memory
const SECRET_ID_RE = /^[a-f0-9]{128}$/;

// In-memory store — never touches disk
const secrets = new Map();

// Rate limiting — per IP, in memory
const rateLimits = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 10; // max 10 creates per minute per IP

// Global rate limit on secret creation
const GLOBAL_RATE_WINDOW = 60 * 1000; // 1 minute
const GLOBAL_RATE_MAX = 100; // max 100 creates per minute total
let globalCreates = { windowStart: Date.now(), count: 0 };

// Rate limiting on failed lookups per IP
const failedLookups = new Map();
const FAILED_LOOKUP_WINDOW = 60 * 1000; // 1 minute
const FAILED_LOOKUP_MAX = 20; // max 20 failed lookups per minute per IP

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimits.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW) {
    rateLimits.set(ip, { windowStart: now, count: 1 });
    return true;
  }
  entry.count++;
  return entry.count <= RATE_LIMIT_MAX;
}

function checkGlobalRate() {
  const now = Date.now();
  if (now - globalCreates.windowStart > GLOBAL_RATE_WINDOW) {
    globalCreates = { windowStart: now, count: 1 };
    return true;
  }
  globalCreates.count++;
  return globalCreates.count <= GLOBAL_RATE_MAX;
}

function checkFailedLookup(ip) {
  const now = Date.now();
  const entry = failedLookups.get(ip);
  if (!entry || now - entry.windowStart > FAILED_LOOKUP_WINDOW) {
    failedLookups.set(ip, { windowStart: now, count: 1 });
    return true;
  }
  entry.count++;
  return entry.count <= FAILED_LOOKUP_MAX;
}

function applyNoStore(res) {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    Pragma: 'no-cache',
    Expires: '0'
  });
}

function sendHtml(res, fileName) {
  applyNoStore(res);
  res.sendFile(path.join(__dirname, 'public', fileName), { lastModified: false });
}

// Clean up expired secrets and stale rate limit entries every 5 minutes
const cleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [id, secret] of secrets) {
    if (now - secret.createdAt > SECRET_TTL) {
      secrets.delete(id);
    }
  }
  for (const [ip, entry] of rateLimits) {
    if (now - entry.windowStart > RATE_LIMIT_WINDOW) {
      rateLimits.delete(ip);
    }
  }
  for (const [ip, entry] of failedLookups) {
    if (now - entry.windowStart > FAILED_LOOKUP_WINDOW) {
      failedLookups.delete(ip);
    }
  }
}, 5 * 60 * 1000);
cleanupInterval.unref();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
      frameAncestors: ["'none'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: 'no-referrer' }
}));
app.use(express.json({ limit: '4kb' }));
app.use((req, res, next) => {
  applyNoStore(res);
  next();
});
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,
  lastModified: false
}));

// Create a secret
app.post('/api/secrets', (req, res) => {
  const ip = req.ip;
  if (!checkRateLimit(ip) || !checkGlobalRate()) {
    return res.status(429).json({ error: 'Too many requests. Try again in a minute.' });
  }

  if (secrets.size >= MAX_SECRETS) {
    return res.status(503).json({ error: 'Server is at capacity. Please try again later.' });
  }

  const { message } = req.body;

  if (!message || typeof message !== 'string' || message.trim().length === 0) {
    return res.status(400).json({ error: 'Message is required' });
  }

  if (message.length > 2048) {
    return res.status(400).json({ error: 'Message too long' });
  }

  const id = crypto.randomBytes(64).toString('hex');

  secrets.set(id, {
    message: message,
    createdAt: Date.now()
  });

  res.status(201).json({ id, url: `/s/${id}` });
});

// Retrieve and destroy a secret (API)
app.get('/api/secrets/:id', (req, res) => {
  const { id } = req.params;

  if (!SECRET_ID_RE.test(id)) {
    return res.status(404).json({ error: 'Secret not found or already viewed' });
  }

  const secret = secrets.get(id);

  if (!secret) {
    if (!checkFailedLookup(req.ip)) {
      return res.status(429).json({ error: 'Too many requests. Try again in a minute.' });
    }
    return res.status(404).json({ error: 'Secret not found or already viewed' });
  }

  // Read then immediately delete
  const message = secret.message;
  secrets.delete(id);

  res.json({ message });
});

// Serve the view page for secret URLs
app.get('/s/:id', (req, res) => {
  if (!SECRET_ID_RE.test(req.params.id)) {
    return res.status(404).send('Not found');
  }

  sendHtml(res, 'view.html');
});

// Fallback to index
app.get('*', (req, res) => {
  sendHtml(res, 'index.html');
});

app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  applyNoStore(res);
  res.status(500).json({ error: 'Internal server error' });
});

function terminateQuietly() {
  clearInterval(cleanupInterval);
  secrets.clear();
  rateLimits.clear();
  failedLookups.clear();

  if (server) {
    server.close(() => process.exit(1));
    setTimeout(() => process.exit(1), 1000).unref();
    return;
  }

  process.exit(1);
}

if (process.report) {
  process.report.reportOnFatalError = false;
  process.report.reportOnUncaughtException = false;
}

process.on('uncaughtException', terminateQuietly);
process.on('unhandledRejection', terminateQuietly);
process.on('SIGINT', terminateQuietly);
process.on('SIGTERM', terminateQuietly);

const server = app.listen(PORT, '127.0.0.1');
server.headersTimeout = 15 * 1000;
server.requestTimeout = 15 * 1000;
server.keepAliveTimeout = 5 * 1000;
server.maxRequestsPerSocket = 100;
server.on('clientError', socket => {
  socket.destroy();
});
