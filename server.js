require('dotenv').config();
const express = require('express');
const session = require('express-session');
const Datastore = require('@seald-io/nedb');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = process.env.PORT || 3000;
const upload = multer({ dest: 'uploads/' });
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const BASE_URL = process.env.BASE_URL || 'http://localhost:' + port;

const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.BREVO_USER,
    pass: process.env.BREVO_PASS
  }
});

const db = new Datastore({ filename: path.join(__dirname, 'users.db'), autoload: true });
const activeSessions = {};

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'ai-mazza-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/success.html', (req, res) => res.sendFile(path.join(__dirname, 'public/success.html')));

function checkAuth(req, res, next) {
  if (!req.session || !req.session.userId) return res.redirect('/login.html');
  next();
}

function checkAdmin(req, res, next) {
  if (!req.session || !req.session.userId || req.session.userRole !== 'admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }
  next();
}

app.get('/', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/index.html', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/abonnement.html', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/abonnement.html')));
app.get('/admin.html', checkAuth, (req, res) => {
  if (req.session.userRole !== 'admin') return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public/admin.html'));
});
app.use(express.static(path.join(__dirname, 'public')));

// ─── SETUP ADMINS ─────────────────────────────────────────────────
app.get('/setup-admin', async (req, res) => {
  try {
    await db.removeAsync({ role: 'admin' }, { multi: true });
    const admins = [
      { email: 'admin@ai-mazza.com', password: 'Mx#9kL$2vP!qR7nT' },
      { email: 'admin2@ai-mazza.com', password: 'Zw@4jF$8mK!xQ3bY' }
    ];
    for (const a of admins) {
      const hash = await bcrypt.hash(a.password, 10);
      await db.insertAsync({ email: a.email, password: hash, role: 'admin', isVerified: true, analysisCount: 0, subscribed: true, banned: false, createdAt: new Date() });
    }
    res.send(`<div style="background:#020510;color:#00f5ff;font-family:monospace;padding:40px;">
      <h2>✅ Admins créés !</h2>
      <p>admin@ai-mazza.com / Mx#9kL$2vP!qR7nT</p>
      <p>admin2@ai-mazza.com / Zw@4jF$8mK!xQ3bY</p>
      <br><a href="/login.html" style="color:#00f5ff;">→ Se connecter</a>
    </div>`);
  } catch(e) { res.send('Erreur: ' + e.message); }
});

// ─── VÉRIFICATION MANUELLE ────────────────────────────────────────
app.get('/verify-manual/:email', async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email).toLowerCase();
    const n = await db.updateAsync({ email }, { $set: { isVerified: true, verifyToken: null } }, {});
    if (n === 0) return res.send('❌ Email introuvable : ' + email);
    res.send(`<div style="background:#020510;color:#00f5ff;font-family:monospace;padding:40px;">
      <h2>✅ Compte vérifié : ${email}</h2>
      <a href="/login.html" style="color:#00f5ff;">→ Se connecter</a>
    </div>`);
  } catch(e) { res.send('Erreur: ' + e.message); }
});

// ─── INSCRIPTION ──────────────────────────────────────────────────
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ error: 'Champs manquants' });
  if (password.length < 6) return res.json({ error: 'Mot de passe trop court (6 min)' });
  try {
    const existing = await db.findOneAsync({ email: email.toLowerCase() });
    if (existing) return res.json({ error: 'Email déjà utilisé' });
    const hash = await bcrypt.hash(password, 10);
    const token = uuidv4();
    await db.insertAsync({
      email: email.toLowerCase(), password: hash,
      role: 'user', isVerified: false,
      verifyToken: token, analysisCount: 0,
      subscribed: false, banned: false,
      createdAt: new Date()
    });
    const verifyUrl = BASE_URL + '/verify/' + token;
    try {
      await transporter.sendMail({
        from: '"AI-Mazza" <' + process.env.BREVO_USER + '>',
        to: email,
        subject: '✅ Confirmez votre compte AI-Mazza',
        html: `
          <div style="background:#020510;font-family:Arial;padding:40px;color:#fff;max-width:500px;margin:auto;border:1px solid #00f5ff;border-radius:4px;">
            <h1 style="color:#00f5ff;letter-spacing:4px;font-size:20px;">AI-MAZZA</h1>
            <div style="height:1px;background:#00f5ff;margin:16px 0 24px;opacity:0.3;"></div>
            <p style="color:rgba(255,255,255,0.8);margin-bottom:8px;">Bienvenue !</p>
            <p style="color:rgba(255,255,255,0.6);margin-bottom:24px;">Confirmez votre email pour activer vos <strong style="color:#00f5ff;">2 analyses gratuites</strong>.</p>
            <a href="${verifyUrl}" style="display:inline-block;background:#00f5ff;color:#020510;padding:14px 32px;text-decoration:none;font-weight:bold;margin:8px 0;border-radius:2px;letter-spacing:2px;font-size:13px;">CONFIRMER MON COMPTE</a>
            <p style="color:rgba(255,255,255,0.3);font-size:11px;margin-top:24px;">Lien valide 24h.</p>
          </div>`
      });
      res.json({ success: 'Compte créé ! Vérifiez votre email pour activer votre compte.' });
    } catch(e) {
      console.log('Email non envoyé:', e.message);
      res.json({ success: 'Compte créé ! (Email non envoyé, contactez le support)' });
    }
  } catch(e) { res.json({ error: 'Erreur: ' + e.message }); }
});

// ─── VÉRIFICATION EMAIL ───────────────────────────────────────────
app.get('/verify/:token', async (req, res) => {
  try {
    const n = await db.updateAsync({ verifyToken: req.params.token }, { $set: { isVerified: true, verifyToken: null } }, {});
    if (n === 0) return res.redirect('/login.html?error=1');
    res.redirect('/login.html?verified=1');
  } catch(e) { res.redirect('/login.html?error=1'); }
});

// ─── RENVOI EMAIL ─────────────────────────────────────────────────
app.post('/resend-email', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await db.findOneAsync({ email: email.toLowerCase() });
    if (!user) return res.json({ error: 'Email introuvable' });
    if (user.isVerified) return res.json({ error: 'Compte déjà vérifié, connectez-vous !' });
    const token = uuidv4();
    await db.updateAsync({ email: email.toLowerCase() }, { $set: { verifyToken: token } }, {});
    const verifyUrl = BASE_URL + '/verify/' + token;
    await transporter.sendMail({
      from: '"AI-Mazza" <' + process.env.BREVO_USER + '>',
      to: email,
      subject: '✅ Nouveau lien de confirmation — AI-Mazza',
      html: `
        <div style="background:#020510;font-family:Arial;padding:40px;color:#fff;max-width:500px;margin:auto;border:1px solid #00f5ff;border-radius:4px;">
          <h1 style="color:#00f5ff;letter-spacing:4px;font-size:20px;">AI-MAZZA</h1>
          <div style="height:1px;background:#00f5ff;margin:16px 0 24px;opacity:0.3;"></div>
          <p style="color:rgba(255,255,255,0.6);margin-bottom:24px;">Voici votre nouveau lien de confirmation :</p>
          <a href="${verifyUrl}" style="display:inline-block;background:#00f5ff;color:#020510;padding:14px 32px;text-decoration:none;font-weight:bold;margin:8px 0;border-radius:2px;letter-spacing:2px;font-size:13px;">CONFIRMER MON COMPTE</a>
          <p style="color:rgba(255,255,255,0.3);font-size:11px;margin-top:24px;">Lien valide 24h.</p>
        </div>`
    });
    res.json({ success: 'Email renvoyé ! Vérifiez votre boîte mail.' });
  } catch(e) { res.json({ error: 'Erreur envoi email: ' + e.message }); }
});

// ─── CONNEXION ────────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ error: 'Champs manquants' });
  try {
    const user = await db.findOneAsync({ email: email.toLowerCase() });
    if (!user) return res.json({ error: 'Email ou mot de passe incorrect' });
    if (!user.isVerified) return res.json({ error: 'email_not_verified' });
    if (user.banned) return res.json({ error: 'Compte banni. Contactez le support.' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ error: 'Email ou mot de passe incorrect' });
    if (user.role !== 'admin') {
      const sessionId = uuidv4();
      activeSessions[user._id] = sessionId;
      req.session.sessionId = sessionId;
    }
    req.session.userId = user._id;
    req.session.userRole = user.role;
    res.json({ success: true, redirect: user.role === 'admin' ? '/admin.html' : '/' });
  } catch(e) { res.json({ error: 'Erreur serveur: ' + e.message }); }
});

// ─── DÉCONNEXION ──────────────────────────────────────────────────
app.get('/logout', (req, res) => {
  if (req.session.userId && req.session.userRole !== 'admin') delete activeSessions[req.session.userId];
  req.session.destroy(() => res.redirect('/login.html'));
});

// ─── INFOS USER ───────────────────────────────────────────────────
app.get('/me', checkAuth, async (req, res) => {
  const user = await db.findOneAsync({ _id: req.session.userId });
  if (!user) return res.json({ error: 'Non trouvé' });
  if (user.role !== 'admin') {
    if (user.banned) { req.session.destroy(); return res.status(403).json({ error: 'banned' }); }
    if (!activeSessions[user._id]) {
      activeSessions[user._id] = req.session.sessionId || uuidv4();
      req.session.sessionId = activeSessions[user._id];
    } else if (activeSessions[user._id] !== req.session.sessionId) {
      req.session.destroy();
      return res.status(401).json({ error: 'session_conflict' });
    }
  }
  res.json({ email: user.email, role: user.role, analysisCount: user.analysisCount, subscribed: user.subscribed });
});

// ─── ANALYSE ──────────────────────────────────────────────────────
app.post('/analyze', checkAuth, upload.single('image'), async (req, res) => {
  try {
    const user = await db.findOneAsync({ _id: req.session.userId });
    if (!user) return res.status(401).json({ error: 'Non connecté' });
    if (user.banned) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(403).json({ error: 'Compte banni' });
    }
    if (user.role !== 'admin') {
      if (activeSessions[user._id] && activeSessions[user._id] !== req.session.sessionId) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        req.session.destroy();
        return res.status(401).json({ error: 'session_conflict' });
      }
    }
    if (user.role !== 'admin' && !user.subscribed && user.analysisCount >= 2) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.json({ limitReached: true, redirect: '/abonnement.html' });
    }
    if (!req.file) return res.status(400).json({ error: 'Aucune image reçue' });

    const capital = parseFloat(req.body.capital) || 0;
    const imageData = fs.readFileSync(req.file.path);
    const base64Image = imageData.toString('base64');
    const mimeType = req.file.mimetype || 'image/png';

    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1500,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: mimeType, data: base64Image } },
          { type: 'text', text: `Tu es un trader Smart Money ICT professionnel avec 15 ans d'expérience.${capital ? ` Capital du trader: $${capital}.` : ''}

Analyse ce graphique et réponds UNIQUEMENT avec un objet JSON valide, sans texte avant ou après, sans backticks:

{
  "decision": "BUY" ou "SELL" ou "NE PAS TRADER",
  "confiance": "XX%",
  "score": <nombre entier de 0 à 10>,
  "tendance": "<description courte de la tendance>",
  "entree": "<prix d'entrée>",
  "sl": "<stop loss>",
  "slPips": <nombre de pips>,
  "tp1": "<take profit 1 RR 1:2>",
  "tp1Pips": <pips tp1>,
  "tp2": "<take profit 2 RR 1:3>",
  "tp3": "<take profit 3 RR 1:4>",
  "ob": "<order block détecté>",
  "fvg": "<fair value gap détecté>",
  "liquidite": "<zones de liquidité>",
  "confluences": "<confluences Smart Money>",
  "invalidation": "<niveau d'invalidation du setup>",
  "lots": ${capital ? `<taille de position en lots calculée sur capital $${capital} avec risque adapté au score>` : 'null'},
  "risquePct": ${capital ? '<pourcentage de risque: 1 si score<6, 2 si score 6-7, 3 si score>=8>' : 'null'},
  "montantRisque": ${capital ? `<montant en dollars risqué calculé sur $${capital}>` : 'null'},
  "capital": ${capital || 0}
}

Règles importantes:
- score 8-10 = setup excellent, risque 3%
- score 6-7 = setup moyen, risque 2%
- score 0-5 = setup faible, NE PAS TRADER, risque 1%
- Les lots doivent être calculés précisément selon le capital et le risque
- Si NE PAS TRADER, mettre score bas et expliquer dans confluences` }
        ]
      }]
    });

    fs.unlinkSync(req.file.path);

    let parsed;
    try {
      const text = response.content[0].text.trim();
      const clean = text.replace(/```json|```/g, '').trim();
      parsed = JSON.parse(clean);
    } catch(e) {
      return res.status(500).json({ error: 'Erreur parsing IA: ' + e.message });
    }

    if (user.role !== 'admin') await db.updateAsync({ _id: user._id }, { $inc: { analysisCount: 1 } }, {});
    const newCount = user.role === 'admin' ? 0 : user.analysisCount + 1;
    const analysesLeft = (user.role === 'admin' || user.subscribed) ? undefined : Math.max(0, 2 - newCount);

    res.json({ ...parsed, analysesLeft, analysisId: uuidv4() });

  } catch (err) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: 'Erreur: ' + err.message });
  }
});

// ─── ADMIN ROUTES ─────────────────────────────────────────────────
app.get('/admin/users', checkAdmin, async (req, res) => {
  try {
    const users = await db.findAsync({ role: { $ne: 'admin' } });
    res.json(users.map(u => ({
      _id: u._id, email: u.email, role: u.role,
      isVerified: u.isVerified, analysisCount: u.analysisCount,
      subscribed: u.subscribed, banned: u.banned || false,
      createdAt: u.createdAt, online: !!activeSessions[u._id]
    })));
  } catch(e) { res.json({ error: e.message }); }
});

app.get('/admin/stats', checkAdmin, async (req, res) => {
  try {
    const users = await db.findAsync({ role: { $ne: 'admin' } });
    res.json({
      total: users.length,
      verified: users.filter(u => u.isVerified).length,
      subscribed: users.filter(u => u.subscribed).length,
      banned: users.filter(u => u.banned).length,
      online: Object.keys(activeSessions).length
    });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/ban/:id', checkAdmin, async (req, res) => {
  try {
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const newBan = !user.banned;
    await db.updateAsync({ _id: req.params.id }, { $set: { banned: newBan } }, {});
    if (newBan) delete activeSessions[req.params.id];
    res.json({ success: true, banned: newBan });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/restrict/:id', checkAdmin, async (req, res) => {
  try {
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisCount: 99, subscribed: false } }, {});
    res.json({ success: true });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/add-analyses/:id', checkAdmin, async (req, res) => {
  try {
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisCount: 0 } }, {});
    res.json({ success: true, newCount: 0 });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/kick/:id', checkAdmin, async (req, res) => {
  try {
    delete activeSessions[req.params.id];
    res.json({ success: true });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/subscribe/:id', checkAdmin, async (req, res) => {
  try {
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const newSub = !user.subscribed;
    await db.updateAsync({ _id: req.params.id }, { $set: { subscribed: newSub } }, {});
    res.json({ success: true, subscribed: newSub });
  } catch(e) { res.json({ error: e.message }); }
});

if (!fs.existsSync(path.join(__dirname, 'uploads'))) fs.mkdirSync(path.join(__dirname, 'uploads'));

app.listen(port, () => {
  console.log('✅ Serveur lancé sur http://localhost:' + port);
});