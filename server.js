require('dotenv').config();
const express = require('express');
const session = require('express-session');
const Datastore = require('@seald-io/nedb');
const bcrypt = require('bcryptjs');
const { Resend } = require('resend');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = process.env.PORT || 3000;
const upload = multer({ dest: 'uploads/' });
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const resend = new Resend(process.env.RESEND_API_KEY);

const db = new Datastore({ filename: path.join(__dirname, 'users.db'), autoload: true });

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'ai-mazza-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ─── CRÉER ADMINS AU DÉMARRAGE ─────────────────────────────────────
const ADMINS = [
  { email: 'admin@ai-mazza.com', password: 'Mx#9kL$2vP!qR7nT' },
  { email: 'admin2@ai-mazza.com', password: 'Zw@4jF$8mK!xQ3bY' }
];

async function createAdmins() {
  for (const admin of ADMINS) {
    db.findOne({ email: admin.email }, async (err, doc) => {
      if (!doc) {
        const hash = await bcrypt.hash(admin.password, 10);
        db.insert({
          email: admin.email, password: hash,
          role: 'admin', isVerified: true,
          analysisCount: 0, subscribed: true,
          createdAt: new Date()
        }, () => console.log('✅ Admin créé:', admin.email));
      }
    });
  }
}

// ─── MIDDLEWARE AUTH ───────────────────────────────────────────────
function checkAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login.html');
}

// ─── ROUTES STATIQUES ─────────────────────────────────────────────
app.get('/', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/abonnement.html', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/abonnement.html')));

// ─── INSCRIPTION ──────────────────────────────────────────────────
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ error: 'Champs manquants' });
  if (password.length < 6) return res.json({ error: 'Mot de passe trop court (6 caractères min)' });

  db.findOne({ email: email.toLowerCase() }, async (err, existing) => {
    if (existing) return res.json({ error: 'Email déjà utilisé' });

    const hash = await bcrypt.hash(password, 10);
    const token = uuidv4();

    db.insert({
      email: email.toLowerCase(), password: hash,
      role: 'user', isVerified: false,
      verifyToken: token, analysisCount: 0,
      subscribed: false, createdAt: new Date()
    }, async (err, doc) => {
      const verifyUrl = (process.env.BASE_URL || 'http://localhost:' + port) + '/verify/' + token;

      try {
        await resend.emails.send({
          from: 'AI-Mazza <onboarding@resend.dev>',
          to: email,
          subject: '✦ Confirmez votre compte AI-Mazza',
          html: `
            <body style="background:#020510;font-family:monospace;padding:40px;color:#fff;">
              <div style="max-width:500px;margin:auto;border:1px solid #00f5ff;padding:40px;background:rgba(0,20,50,0.9);">
                <h1 style="color:#00f5ff;letter-spacing:6px;font-size:22px;">AI-MAZZA</h1>
                <div style="height:1px;background:#00f5ff;margin:16px 0 24px;"></div>
                <p style="color:rgba(255,255,255,0.7);margin-bottom:24px;">Confirmez votre email pour activer vos 2 analyses gratuites.</p>
                <a href="${verifyUrl}" style="display:inline-block;border:1px solid #00f5ff;color:#00f5ff;padding:14px 32px;text-decoration:none;letter-spacing:3px;text-transform:uppercase;font-size:12px;">
                  CONFIRMER MON COMPTE
                </a>
                <p style="color:rgba(255,255,255,0.3);font-size:11px;margin-top:24px;">Lien valide 24h.</p>
              </div>
            </body>
          `
        });
      } catch (e) { console.log('Email non envoyé:', e.message); }

      res.json({ success: true });
    });
  });
});

// ─── VÉRIFICATION EMAIL ────────────────────────────────────────────
app.get('/verify/:token', (req, res) => {
  db.update({ verifyToken: req.params.token }, { $set: { isVerified: true, verifyToken: null } }, {}, (err, n) => {
    if (n === 0) return res.redirect('/login.html?error=1');
    res.redirect('/login.html?verified=1');
  });
});

// ─── CONNEXION ────────────────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ error: 'Champs manquants' });

  db.findOne({ email: email.toLowerCase() }, async (err, user) => {
    if (!user) return res.json({ error: 'Email ou mot de passe incorrect' });
    if (!user.isVerified) return res.json({ error: 'Vérifiez votre email avant de vous connecter' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ error: 'Email ou mot de passe incorrect' });

    req.session.userId = user._id;
    req.session.userRole = user.role;
    res.json({ success: true, redirect: '/' });
  });
});

// ─── DÉCONNEXION ──────────────────────────────────────────────────
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

// ─── STATUT SESSION ───────────────────────────────────────────────
app.get('/me', checkAuth, (req, res) => {
  db.findOne({ _id: req.session.userId }, (err, user) => {
    if (!user) return res.json({ error: 'Non trouvé' });
    res.json({
      email: user.email, role: user.role,
      analysisCount: user.analysisCount, subscribed: user.subscribed
    });
  });
});

// ─── ANALYSE ──────────────────────────────────────────────────────
app.post('/analyze', checkAuth, upload.single('image'), async (req, res) => {
  db.findOne({ _id: req.session.userId }, async (err, user) => {
    if (!user) return res.status(401).json({ error: 'Non connecté' });

    if (user.role !== 'admin' && !user.subscribed && user.analysisCount >= 2) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.json({ limitReached: true, redirect: '/abonnement.html' });
    }

    if (!req.file) return res.status(400).json({ error: 'Aucune image reçue' });

    try {
      const imageData = fs.readFileSync(req.file.path);
      const base64Image = imageData.toString('base64');
      const mimeType = req.file.mimetype || 'image/png';

      const response = await client.messages.create({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: mimeType, data: base64Image } },
            { type: 'text', text: `Tu es un trader professionnel avec 15 ans d'expérience. Analyse ce graphique et réponds en français avec exactement ce format :

DÉCISION: BUY ou SELL — Confiance XX%

TENDANCE: [2-3 phrases max, direct et cash]

ENTRÉE: [prix précis ou zone ex: 4500 - 4520]

STOP LOSS: [prix précis ex: 4450]

TAKE PROFIT: [prix précis ex: 4650]

SETUP: [2-3 phrases sur les indicateurs, bref et concret]

IMPORTANT: Sois direct comme un vrai trader. Pas de blabla. Phrases courtes. Donne des chiffres précis.` }
          ]
        }]
      });

      fs.unlinkSync(req.file.path);

      if (user.role !== 'admin') {
        db.update({ _id: user._id }, { $inc: { analysisCount: 1 } }, {});
      }

      const newCount = user.role === 'admin' ? null : user.analysisCount + 1;
      const analysesLeft = user.role === 'admin' || user.subscribed ? null : Math.max(0, 2 - newCount);

      res.json({ result: response.content[0].text, analysesLeft });

    } catch (err) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      res.status(500).json({ error: 'Erreur: ' + err.message });
    }
  });
});

// ─── DÉMARRAGE ────────────────────────────────────────────────────
if (!fs.existsSync(path.join(__dirname, 'uploads'))) fs.mkdirSync(path.join(__dirname, 'uploads'));

app.listen(port, async () => {
  console.log('✅ Serveur lancé sur http://localhost:' + port);
  await createAdmins();
});