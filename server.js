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
const BASE_URL = process.env.BASE_URL || 'http://localhost:' + port;

const db = new Datastore({ filename: path.join(__dirname, 'users.db'), autoload: true });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret123',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Pages publiques
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/success.html', (req, res) => res.sendFile(path.join(__dirname, 'public/success.html')));

// Auth middleware
function checkAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login.html');
}

// Pages protégées
app.get('/', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/index.html', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/abonnement.html', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/abonnement.html')));

// Fichiers statiques
app.use(express.static(path.join(__dirname, 'public')));

// Créer admins
async function createAdmins() {
  const admins = [
    { email: 'admin@trading-ia.com', password: 'Admin2024!' },
    { email: 'admin2@trading-ia.com', password: 'Admin2024bis!' }
  ];
  for (const a of admins) {
    const existing = await db.findOneAsync({ email: a.email });
    if (!existing) {
      const hash = await bcrypt.hash(a.password, 10);
      await db.insertAsync({
        email: a.email, password: hash,
        role: 'admin', isVerified: true,
        analysisCount: 0, subscribed: true,
        createdAt: new Date()
      });
      console.log('✅ Admin créé:', a.email, '/', a.password);
    }
  }
}

// ===== INSCRIPTION =====
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ error: 'Champs manquants' });
  if (password.length < 6) return res.json({ error: 'Mot de passe trop court (6 min)' });

  const existing = await db.findOneAsync({ email: email.toLowerCase() });
  if (existing) return res.json({ error: 'Email déjà utilisé' });

  const hash = await bcrypt.hash(password, 10);
  const token = uuidv4();

  await db.insertAsync({
    email: email.toLowerCase(), password: hash,
    role: 'user', isVerified: false,
    verifyToken: token, analysisCount: 0,
    subscribed: false, createdAt: new Date()
  });

  try {
    await resend.emails.send({
      from: 'IA Trading <onboarding@resend.dev>',
      to: email,
      subject: '✅ Confirmez votre compte IA Trading',
      html: `
        <div style="background:#020510;font-family:Arial;padding:40px;color:#fff;max-width:500px;margin:auto;border:1px solid #00f5ff;">
          <h1 style="color:#00f5ff;letter-spacing:4px;">🤖 IA DE TRADING</h1>
          <p>Confirmez votre email pour activer vos 2 analyses gratuites.</p>
          <a href="${BASE_URL}/verify/${token}"
             style="display:inline-block;background:#00f5ff;color:#020510;padding:14px 28px;text-decoration:none;font-weight:bold;margin:20px 0;border-radius:2px;">
            CONFIRMER MON COMPTE
          </a>
          <p style="color:rgba(255,255,255,0.3);font-size:11px;">Lien valide 24h.</p>
        </div>
      `
    });
  } catch(e) {
    console.log('Email non envoyé:', e.message);
  }

  res.json({ success: 'Compte créé ! Vérifiez votre email pour activer votre compte.' });
});

// ===== VÉRIFICATION EMAIL =====
app.get('/verify/:token', async (req, res) => {
  const n = await db.updateAsync(
    { verifyToken: req.params.token },
    { $set: { isVerified: true, verifyToken: null } },
    {}
  );
  if (n === 0) return res.redirect('/login.html?error=1');
  res.redirect('/login.html?verified=1');
});

// ===== RENVOI EMAIL =====
app.post('/resend-email', async (req, res) => {
  const { email } = req.body;
  const user = await db.findOneAsync({ email: email.toLowerCase() });
  if (!user) return res.json({ error: 'Email introuvable' });
  if (user.isVerified) return res.json({ error: 'Compte déjà vérifié' });

  const token = uuidv4();
  await db.updateAsync({ email: email.toLowerCase() }, { $set: { verifyToken: token } }, {});

  try {
    await resend.emails.send({
      from: 'IA Trading <onboarding@resend.dev>',
      to: email,
      subject: '✅ Nouveau lien de confirmation',
      html: `
        <div style="background:#020510;padding:40px;color:#fff;max-width:500px;margin:auto;border:1px solid #00f5ff;">
          <h1 style="color:#00f5ff;">🤖 IA DE TRADING</h1>
          <a href="${BASE_URL}/verify/${token}"
             style="display:inline-block;background:#00f5ff;color:#020510;padding:14px 28px;text-decoration:none;font-weight:bold;margin:20px 0;">
            CONFIRMER MON COMPTE
          </a>
        </div>
      `
    });
    res.json({ success: 'Email renvoyé !' });
  } catch(e) {
    res.json({ error: 'Erreur envoi email' });
  }
});

// ===== CONNEXION =====
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ error: 'Champs manquants' });

  const user = await db.findOneAsync({ email: email.toLowerCase() });
  if (!user) return res.json({ error: 'Email ou mot de passe incorrect' });
  if (!user.isVerified) return res.json({ error: 'Vérifiez votre email avant de vous connecter' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ error: 'Email ou mot de passe incorrect' });

  req.session.userId = user._id;
  req.session.userRole = user.role;
  res.json({ success: true, redirect: '/' });
});

// ===== DÉCONNEXION =====
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

// ===== INFOS USER =====
app.get('/me', checkAuth, (req, res) => {
  db.findOne({ _id: req.session.userId }, (err, user) => {
    if (!user) return res.json({ error: 'Non trouvé' });
    res.json({
      email: user.email,
      role: user.role,
      analysisCount: user.analysisCount,
      subscribed: user.subscribed
    });
  });
});

// ===== ANALYSE =====
app.post('/analyze', checkAuth, upload.single('image'), async (req, res) => {
  const user = await db.findOneAsync({ _id: req.session.userId });
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
      await db.updateAsync({ _id: user._id }, { $inc: { analysisCount: 1 } }, {});
    }

    const newCount = user.role === 'admin' ? 0 : user.analysisCount + 1;
    const analysesLeft = (user.role === 'admin' || user.subscribed) ? null : Math.max(0, 2 - newCount);

    res.json({ result: response.content[0].text, analysesLeft });

  } catch (err) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: 'Erreur: ' + err.message });
  }
});

// Démarrage
if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
  fs.mkdirSync(path.join(__dirname, 'uploads'));
}

app.listen(port, async () => {
  console.log('✅ Serveur lancé sur http://localhost:' + port);
  await createAdmins();
});