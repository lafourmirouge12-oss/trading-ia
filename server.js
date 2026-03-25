require('dotenv').config({ path: __dirname + '/.env' });
const express = require('express');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const { Resend } = require('resend');
const Datastore = require('@seald-io/nedb');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const upload = multer({ dest: 'uploads/' });
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const resend = new Resend(process.env.RESEND_API_KEY);

const db = new Datastore({
  filename: path.join(__dirname, 'users.db'),
  autoload: true
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret123',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login.html');
  next();
}

app.get('/', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/index.html', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/abonnement.html', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/abonnement.html')));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/create-admin', async (req, res) => {
  try {
    const hash = await bcrypt.hash('Admin2024!', 10);
    await db.removeAsync({ email: 'admin@trading-ia.com' }, { multi: true });
    await db.insertAsync({
      email: 'admin@trading-ia.com',
      password: hash,
      name: 'Admin',
      role: 'admin',
      verified: true,
      analysisCount: 0,
      subscribed: true,
      createdAt: new Date()
    });
    res.send('✅ Admin créé ! Allez sur /login.html et connectez-vous avec admin@trading-ia.com / Admin2024!');
  } catch(e) {
    res.send('Erreur: ' + e.message);
  }
});

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.json({ error: 'Tous les champs sont requis' });

  try {
    const existing = await db.findOneAsync({ email: email.trim().toLowerCase() });
    if (existing) return res.json({ error: 'Email déjà utilisé' });

    const hash = await bcrypt.hash(password, 10);
    const token = uuidv4();

    await db.insertAsync({
      name,
      email: email.trim().toLowerCase(),
      password: hash,
      role: 'user',
      verified: false,
      verifyToken: token,
      analysisCount: 0,
      subscribed: false,
      createdAt: new Date()
    });

    try {
      await resend.emails.send({
        from: process.env.EMAIL_FROM || 'onboarding@resend.dev',
        to: email,
        subject: '✅ Vérifiez votre compte IA Trading',
        html: `
          <div style="font-family:Arial;max-width:500px;margin:auto;background:#020510;color:white;padding:40px;border-radius:10px;">
            <h1 style="color:#00f5ff;">🤖 IA de Trading</h1>
            <p>Bonjour ${name},</p>
            <p>Cliquez ci-dessous pour vérifier votre compte :</p>
            <a href="${process.env.SITE_URL || 'http://localhost:3000'}/verify?token=${token}"
               style="display:inline-block;background:#00f5ff;color:#020510;padding:14px 28px;border-radius:4px;text-decoration:none;font-weight:bold;margin:20px 0;">
              Vérifier mon compte
            </a>
          </div>
        `
      });
    } catch(e) {
      console.log('Email non envoyé:', e.message);
    }

    res.json({ success: true, message: 'Compte créé ! Vérifiez votre email.' });
  } catch(e) {
    res.json({ error: 'Erreur: ' + e.message });
  }
});

app.get('/verify', async (req, res) => {
  const { token } = req.query;
  const n = await db.updateAsync({ verifyToken: token }, { $set: { verified: true, verifyToken: null } }, {});
  if (n === 0) return res.redirect('/login.html?error=token_invalide');
  res.redirect('/login.html?verified=1');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ error: 'Remplissez tous les champs' });

  try {
    const user = await db.findOneAsync({ email: email.trim().toLowerCase() });
    if (!user) return res.json({ error: 'Email ou mot de passe incorrect' });
    if (!user.verified) return res.json({ error: 'Vérifiez votre email avant de vous connecter' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ error: 'Email ou mot de passe incorrect' });

    req.session.user = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      analysisCount: user.analysisCount,
      subscribed: user.subscribed
    };

    res.json({ success: true, role: user.role });
  } catch(e) {
    res.json({ error: 'Erreur serveur: ' + e.message });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

app.get('/me', requireAuth, (req, res) => {
  res.json(req.session.user);
});

app.post('/analyze', requireAuth, upload.single('image'), async (req, res) => {
  const user = req.session.user;

  if (user.role !== 'admin') {
    if (!user.subscribed && user.analysisCount >= 2) {
      return res.status(403).json({ redirect: '/abonnement.html', error: 'Limite atteinte — Abonnez-vous pour continuer' });
    }
  }

  try {
    if (!req.file) return res.status(400).json({ error: 'Aucune image reçue' });

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
          {
            type: 'text',
            text: `Tu es un trader professionnel avec 15 ans d'expérience. Analyse ce graphique et réponds en français avec exactement ce format :

DÉCISION: BUY ou SELL — Confiance XX%

TENDANCE: [2-3 phrases max, direct et cash]

ENTRÉE: [prix précis ou zone ex: 4500 - 4520]

STOP LOSS: [prix précis ex: 4450]

TAKE PROFIT: [prix précis ex: 4650]

SETUP: [2-3 phrases sur les indicateurs, bref et concret]

IMPORTANT: Sois direct comme un vrai trader. Pas de blabla. Phrases courtes. Donne des chiffres précis.`
          }
        ]
      }]
    });

    fs.unlinkSync(req.file.path);

    if (user.role !== 'admin') {
      const newCount = user.analysisCount + 1;
      await db.updateAsync({ _id: user.id }, { $inc: { analysisCount: 1 } }, {});
      req.session.user.analysisCount = newCount;
    }

    res.json({
      result: response.content[0].text,
      analysisCount: req.session.user.analysisCount,
      subscribed: user.subscribed,
      isAdmin: user.role === 'admin'
    });

  } catch (err) {
    console.error('Erreur:', err.message);
    res.status(500).json({ error: 'Erreur : ' + err.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Serveur lancé sur http://localhost:${PORT}`);
});