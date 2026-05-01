'use strict';

const cluster = require('cluster');
const os = require('os');
const crypto = require('crypto');

// Primary process: manage worker pool and shared session secret
// Worker processes: run the Express server with shared session store and security features
// This design allows us to utilize all CPU cores for handling requests while maintaining a single source of truth for session secrets and a shared session store via SQLite.
if (cluster.isPrimary) {
  // Generate one session secret shared by all workers before forking.
  // Each worker inherits it via process.env, so sessions signed by one
  // worker can be verified by any other.
  process.env.SESSION_SECRET =
    process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

  const cpus = os.cpus().length;
  console.log(`Primary ${process.pid}: spawning ${cpus} workers (one per CPU core)`);

  for (let i = 0; i < cpus; i++) cluster.fork();

  // Auto-restart any worker that crashes
  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} exited (${signal || code}) — restarting`);
    cluster.fork();
  });

} else {
  // Run the Express server
  const express = require('express');
  const session = require('express-session');
  const SqliteStore = require('better-sqlite3-session-store')(session);
  const rateLimit = require('express-rate-limit');
  const helmet = require('helmet');
  const bcrypt = require('bcryptjs');
  const compression = require('compression');
  const Database = require('better-sqlite3');
  const path = require('path');

  const app = express();
  const PORT = process.env.PORT || 3000;

  // Database setup
  const db = new Database(path.join(__dirname, 'database.db'));
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Gzip/Brotli compress all responses before sending
  app.use(compression());

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        fontSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"]
      }
    },
    referrerPolicy: { policy: 'no-referrer' }
  }));

  // Middleware 
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());

  // Persistent SQLite session store — survives restarts, shared across all
  // worker processes via the same database file
  app.use(session({
    store: new SqliteStore({
      client:  db,
      expired: { clear: true, intervalMs: 900_000 } // purge expired sessions every 15 min
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,     // JS cannot read the cookie
      secure: false,      // set true in production (HTTPS)
      sameSite: 'strict', // blocks CSRF
      maxAge: 3_600_000   // 1 hour
    }
  }));

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.use(express.static(path.join(__dirname, 'public')));

  // CSRF token helpers
  function csrfToken(req) {
    if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString('hex');
    return req.session.csrf;
  }

  function verifyCsrf(req, res, next) {
    if (!req.body._csrf || req.body._csrf !== req.session.csrf) {
      return res.status(403).send('Invalid CSRF token - request blocked.');
    }
    next();
  }

  // Rate limiter 
  // Note: counters are per-worker (in-memory). With N workers, up to N×10
  // attempts are possible before a block.
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts from this IP. Please wait 15 minutes.'
  });

  // Auth guard 
  function requireAuth(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    next();
  }

  // Routes 

  app.get('/login', (req, res) => {
    res.render('login', { error: null, csrf: csrfToken(req) });
  });

  app.post('/login', loginLimiter, verifyCsrf, (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.render('login', { error: 'Invalid username or password.', csrf: csrfToken(req) });
    }
    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect('/dashboard');
  });

  app.get('/register', (req, res) => {
    res.render('register', { error: null, csrf: csrfToken(req) });
  });

  app.post('/register', verifyCsrf, (req, res) => {
    const { username, password } = req.body;
    if (!username || username.length < 3 || !password || password.length < 6) {
      return res.render('register', {
        error: 'Username must be 3+ characters and password 6+ characters.',
        csrf: csrfToken(req)
      });
    }
    const hash = bcrypt.hashSync(password, 12);
    try {
      db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
      const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
      req.session.userId = user.id;
      req.session.username = username;
      res.redirect('/dashboard');
    } catch (err) {
      const msg = err.message.includes('UNIQUE') ? 'Username already taken.' : 'Registration failed. Try again.';
      res.render('register', { error: msg, csrf: csrfToken(req) });
    }
  });

  app.get('/dashboard', requireAuth, (req, res) => {
    res.render('dashboard', { username: req.session.username, csrf: csrfToken(req) });
  });

  app.post('/logout', verifyCsrf, (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
  });

  app.listen(PORT, '::', () => {
    console.log(`Worker ${process.pid} → http://localhost:${PORT}`);
  });
}