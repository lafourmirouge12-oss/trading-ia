require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const Datastore = require('@seald-io/nedb');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch');
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

const db = new Datastore({ filename: path.join(__dirname, 'users.db'), autoload: true });
const activeSessions = {};

async function sendEmail(to, subject, html) {
  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'api-key': process.env.BREVO_API_KEY },
    body: JSON.stringify({
      sender: { name: 'J4keIA', email: 'tradingsupport68@gmail.com' },
      to: [{ email: to }], subject, htmlContent: html
    })
  });
  if (!response.ok) throw new Error('Brevo: ' + await response.text());
  return response.json();
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'j4keia-secret-2024',
  resave: false,
  saveUninitialized: false,
  store: new MemoryStore({ checkPeriod: 86400000 }),
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
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

app.get('/setup-admin', async (req, res) => {
  try {
    await db.removeAsync({ role: 'admin' }, { multi: true });
    const admins = [
      { email: 'admin@ai-mazza.com', password: 'Mx#9kL$2vP!qR7nT' },
      { email: 'admin2@ai-mazza.com', password: 'Zw@4jF$8mK!xQ3bY' }
    ];
    for (const a of admins) {
      const hash = await bcrypt.hash(a.password, 10);
      await db.insertAsync({ email: a.email, password: hash, role: 'admin', isVerified: true, analysisCount: 0, analysisMax: 999999, subscribed: true, plan: 'elite', banned: false, createdAt: new Date() });
    }
    res.send(`<div style="background:#020510;color:#00f5ff;font-family:monospace;padding:40px;">
      <h2>✅ Admins créés !</h2>
      <p>admin@ai-mazza.com / Mx#9kL$2vP!qR7nT</p>
      <p>admin2@ai-mazza.com / Zw@4jF$8mK!xQ3bY</p>
      <br><a href="/login.html" style="color:#00f5ff;">→ Se connecter</a>
    </div>`);
  } catch(e) { res.send('Erreur: ' + e.message); }
});

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
      analysisMax: 0, subscribed: false,
      plan: 'free', banned: false,
      paymentStatus: 'pending', paymentNote: '',
      createdAt: new Date()
    });
    const verifyUrl = BASE_URL + '/verify/' + token;
    try {
      await sendEmail(email, '✅ Confirmez votre compte J4keIA', `
        <div style="background:#020510;font-family:Arial;padding:40px;color:#fff;max-width:500px;margin:auto;border:1px solid #00f5ff;border-radius:4px;">
          <h1 style="color:#00f5ff;letter-spacing:4px;font-size:20px;">J4keIA</h1>
          <div style="height:1px;background:#00f5ff;margin:16px 0 24px;opacity:0.3;"></div>
          <p style="color:rgba(255,255,255,0.6);margin-bottom:24px;">Confirmez votre email pour accéder à la plateforme.</p>
          <a href="${verifyUrl}" style="display:inline-block;background:#00f5ff;color:#020510;padding:14px 32px;text-decoration:none;font-weight:bold;margin:8px 0;border-radius:2px;letter-spacing:2px;font-size:13px;">CONFIRMER MON COMPTE</a>
          <p style="color:rgba(255,255,255,0.3);font-size:11px;margin-top:24px;">Lien valide 24h.</p>
        </div>`);
      res.json({ success: 'Compte créé ! Vérifiez votre email.' });
    } catch(e) {
      console.log('Email non envoyé:', e.message);
      res.json({ success: 'Compte créé ! (Email non envoyé, contactez le support)' });
    }
  } catch(e) { res.json({ error: 'Erreur: ' + e.message }); }
});

app.get('/verify/:token', async (req, res) => {
  try {
    const n = await db.updateAsync({ verifyToken: req.params.token }, { $set: { isVerified: true, verifyToken: null } }, {});
    if (n === 0) return res.redirect('/login.html?error=1');
    res.redirect('/login.html?verified=1');
  } catch(e) { res.redirect('/login.html?error=1'); }
});

app.post('/resend-email', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await db.findOneAsync({ email: email.toLowerCase() });
    if (!user) return res.json({ error: 'Email introuvable' });
    if (user.isVerified) return res.json({ error: 'Compte déjà vérifié !' });
    const token = uuidv4();
    await db.updateAsync({ email: email.toLowerCase() }, { $set: { verifyToken: token } }, {});
    const verifyUrl = BASE_URL + '/verify/' + token;
    await sendEmail(email, '✅ Nouveau lien — J4keIA', `
      <div style="background:#020510;font-family:Arial;padding:40px;color:#fff;max-width:500px;margin:auto;border:1px solid #00f5ff;border-radius:4px;">
        <h1 style="color:#00f5ff;letter-spacing:4px;font-size:20px;">J4keIA</h1>
        <a href="${verifyUrl}" style="display:inline-block;background:#00f5ff;color:#020510;padding:14px 32px;text-decoration:none;font-weight:bold;margin:24px 0;border-radius:2px;letter-spacing:2px;font-size:13px;">CONFIRMER MON COMPTE</a>
        <p style="color:rgba(255,255,255,0.3);font-size:11px;">Lien valide 24h.</p>
      </div>`);
    res.json({ success: 'Email renvoyé !' });
  } catch(e) { res.json({ error: 'Erreur: ' + e.message }); }
});

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

app.get('/logout', (req, res) => {
  if (req.session.userId && req.session.userRole !== 'admin') delete activeSessions[req.session.userId];
  req.session.destroy(() => res.redirect('/login.html'));
});

app.get('/me', checkAuth, async (req, res) => {
  const user = await db.findOneAsync({ _id: req.session.userId });
  if (!user) return res.json({ error: 'Non trouvé' });
  if (user.role !== 'admin') {
    if (activeSessions[user._id] && activeSessions[user._id] !== req.session.sessionId) {
      req.session.destroy();
      return res.status(401).json({ error: 'session_conflict' });
    }
    if (user.banned) { req.session.destroy(); return res.status(403).json({ error: 'banned' }); }
  }
  const analysisMax = user.role === 'admin' ? 999999 : (user.analysisMax || 0);
  const analysesLeft = user.role === 'admin' ? 999999 : Math.max(0, analysisMax - (user.analysisCount || 0));
  res.json({ email: user.email, role: user.role, analysisCount: user.analysisCount || 0, analysisMax, analysesLeft, subscribed: user.subscribed, plan: user.plan || 'free' });
});

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
      const analysisMax = user.analysisMax || 0;
      if ((user.analysisCount || 0) >= analysisMax) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        return res.json({ limitReached: true, redirect: '/abonnement.html' });
      }
    }
    if (!req.file) return res.status(400).json({ error: 'Aucune image reçue' });

    const capital = parseFloat(req.body.capital) || 0;
    const imageData = fs.readFileSync(req.file.path);
    const base64Image = imageData.toString('base64');
    const mimeType = req.file.mimetype || 'image/png';

    // Calcul serveur des limites de lots selon capital
    const lotsMaxXAU = capital > 0 ? Math.min(0.50, Math.floor((capital * 0.05) / 10 * 100) / 100) : 0.05;
    const lotsMaxForex = capital > 0 ? Math.min(0.50, Math.floor((capital * 0.05) / 10 * 100) / 100) : 0.05;
    const lotsMaxCrypto = capital > 0 ? Math.min(0.50, Math.floor((capital * 0.05) / 100 * 100) / 100) : 0.01;

    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1200,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: mimeType, data: base64Image } },
          { type: 'text', text: `Tu es un trader Smart Money institutionnel avec 20 ans d'expérience. Tu analyses les marchés comme les grandes banques et hedge funds en utilisant les concepts ICT/Smart Money.

INFORMATIONS COMPTE VTMARKETS :
- Levier : 500:1 (fixe pour tous les clients)
- Plateforme : MetaTrader 5

${capital > 0 ? `Capital du trader : $${capital}

RÈGLE DU RISQUE ADAPTÉ :
- Évalue la qualité du setup sur 10
- Score 8-10/10 : risque 5% = $${(capital*0.05).toFixed(2)}
- Score 5-7/10 : risque 3% = $${(capital*0.03).toFixed(2)}
- Score 1-4/10 : NE PAS TRADER

CALCULATEUR DE LOTS SÉCURISÉ — CAPITAL $${capital} :

RÈGLE ABSOLUE DE SÉCURITÉ :
- Lots MAXIMUM autorisé : ${lotsMaxXAU} lots (calculé selon votre capital)
- Ne JAMAIS dépasser cette limite quelque soit le SL
- Si le calcul dépasse la limite → utiliser la limite maximale

FORMULES PAR ACTIF :
XAUUSD (Or) :
- Lots = Montant risqué / (SL en points × 0.1)
- MAXIMUM ABSOLU : ${lotsMaxXAU} lots pour votre capital
- Exemple capital $300 risque 5%=$15, SL 150pts → 15/(150×0.1)=1.00 → plafonné à ${lotsMaxXAU} lots

FOREX (EURUSD, GBPUSD, USDJPY...) :
- Lots = Montant risqué / (SL en pips × 10)
- MAXIMUM ABSOLU : ${lotsMaxForex} lots pour votre capital

PÉTROLE (XTIUSD/USOIL) :
- Lots = Montant risqué / (SL en points × 0.1)
- MAXIMUM ABSOLU : ${lotsMaxForex} lots pour votre capital

INDICES (US30, NAS100, SPX500) :
- Lots = Montant risqué / (SL en points × 1)
- MAXIMUM ABSOLU : 0.10 lots pour capital sous $500

CRYPTO (BTCUSD, ETHUSD) :
- Lots = Montant risqué / (SL en points × 1)
- MAXIMUM ABSOLU : ${lotsMaxCrypto} lots pour votre capital` : ''}

MÉTHODOLOGIE SMART MONEY — ANALYSE DANS CET ORDRE :

1. STRUCTURE DU MARCHÉ :
- Identifier Higher High (HH), Higher Low (HL), Lower High (LH), Lower Low (LL)
- Détecter Break of Structure (BOS) = continuation
- Détecter Change of Character (CHOCH) = retournement
- Tendance institutionnelle réelle

2. ZONES INSTITUTIONNELLES :
- Order Block (OB) haussier : dernière bougie bearish avant mouvement bullish fort
- Order Block (OB) baissier : dernière bougie bullish avant mouvement bearish fort
- Fair Value Gap (FVG) : déséquilibre entre bougie 1 et bougie 3
- Premium/Discount : au-dessus du 50% du range = premium (vendre), en-dessous = discount (acheter)

3. LIQUIDITÉ :
- Equal Highs/Lows : zones de stops retail évidents
- Liquidity Sweep : chasse aux stops avant vrai mouvement
- Buy Side Liquidity (BSL) : stops des vendeurs au-dessus des highs
- Sell Side Liquidity (SSL) : stops des acheteurs en-dessous des lows

4. CONFLUENCE :
- OB + FVG + RSI extrême = setup A+ (9-10/10)
- OB + FVG = setup fort (7-8/10)
- OB seul ou FVG seul = setup moyen (5-6/10)
- Aucune confluence = NE PAS TRADER (1-4/10)

RÈGLES RR ABSOLUES :
- RR MINIMUM 1:2 obligatoire sur TP1
- TP2 minimum RR 1:3
- TP3 minimum RR 1:4
- Si RR impossible → NE PAS TRADER

Réponds EXACTEMENT dans ce format sans markdown sans astérisques :

DÉCISION: BUY ou SELL — Confiance : XX%
SCORE SETUP: X/10

STRUCTURE: [HH/HL ou LH/LL — BOS ou CHOCH — tendance institutionnelle]

SMART MONEY:
Order Block : [zone de prix ex: 3280-3285 ou aucun]
Fair Value Gap : [zone de prix ou aucun]
Liquidité : [BSL ou SSL chassée oui/non + explication]
Zone : [Premium ou Discount]

Entrée : [prix précis dans OB ou FVG]
Stop Loss : [prix précis sous/au-dessus OB] (XX pips)
Take Profit 1 : [prix précis] (XX pips) — RR 1:2
Take Profit 2 : [prix précis] (XX pips) — RR 1:3
Take Profit 3 : [prix précis] (XX pips) — RR 1:4
Break Even : Déplacer SL à l'entrée dès que TP1 atteint

RSI: [valeur précise + signal]
CONFLUENCE: [résumé des confluences Smart Money]

${capital > 0 ? `GESTION CAPITAL ($${capital}) — Levier 500:1 VTMarkets :
Score : X/10 — Risque choisi : X% — Montant risqué : $XX
LOTS A TRADER : X.XX lots (maximum autorisé : ${lotsMaxXAU} lots)
Marge requise : $XX` : ''}

INVALIDATION: [niveau précis qui invalide le setup]

IMPORTANT : Respecter ABSOLUMENT la limite de lots. Prix sans symboles. RR minimum 1:2.` }
        ]
      }]
    });

    fs.unlinkSync(req.file.path);
    if (user.role !== 'admin') {
      await db.updateAsync({ _id: user._id }, { $inc: { analysisCount: 1 } }, {});
    }
    const analysisMax = user.role === 'admin' ? 999999 : (user.analysisMax || 0);
    const newCount = user.role === 'admin' ? 0 : (user.analysisCount || 0) + 1;
    const newLeft = user.role === 'admin' ? 999999 : Math.max(0, analysisMax - newCount);
    res.json({ result: response.content[0].text, analysesLeft: newLeft, capital });
  } catch (err) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    console.error('Erreur analyze:', err.message);
    res.status(500).json({ error: 'Erreur: ' + err.message });
  }
});

app.post('/feedback', checkAuth, async (req, res) => {
  try {
    const { result, capital, decision, entry, sl, tp } = req.body;
    const user = await db.findOneAsync({ _id: req.session.userId });
    if (!user) return res.json({ error: 'Non connecté' });
    await db.insertAsync({
      type: 'feedback', userId: req.session.userId,
      email: user.email, result, capital, decision, entry, sl, tp,
      createdAt: new Date()
    });
    res.json({ success: true });
  } catch(e) { res.json({ error: e.message }); }
});

app.get('/admin/users', checkAdmin, async (req, res) => {
  try {
    const users = await db.findAsync({ role: { $ne: 'admin' } });
    res.json(users.map(u => ({
      _id: u._id, email: u.email, isVerified: u.isVerified,
      analysisCount: u.analysisCount || 0, analysisMax: u.analysisMax || 0,
      subscribed: u.subscribed || false, plan: u.plan || 'free',
      banned: u.banned || false, createdAt: u.createdAt,
      online: !!activeSessions[u._id],
      paymentStatus: u.paymentStatus || 'pending', paymentNote: u.paymentNote || ''
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
      online: Object.keys(activeSessions).length,
      paid: users.filter(u => u.paymentStatus === 'paid').length,
      pending: users.filter(u => u.paymentStatus !== 'paid').length
    });
  } catch(e) { res.json({ error: e.message }); }
});

app.get('/admin/feedback', checkAdmin, async (req, res) => {
  try {
    const feedbacks = await db.findAsync({ type: 'feedback' });
    const tp = feedbacks.filter(f => f.result === 'tp').length;
    const sl = feedbacks.filter(f => f.result === 'sl').length;
    const pending = feedbacks.filter(f => f.result === 'pending').length;
    const winrate = (tp + sl) > 0 ? ((tp / (tp + sl)) * 100).toFixed(1) : 0;
    res.json({ total: feedbacks.length, tp, sl, pending, winrate });
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
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisCount: 0, analysisMax: 0, subscribed: false } }, {});
    res.json({ success: true });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/add-one/:id', checkAdmin, async (req, res) => {
  try {
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const newMax = (user.analysisMax || 0) + 1;
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisMax: newMax } }, {});
    res.json({ success: true, analysisMax: newMax });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/remove-one/:id', checkAdmin, async (req, res) => {
  try {
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const newMax = Math.max(0, (user.analysisMax || 0) - 1);
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisMax: newMax } }, {});
    res.json({ success: true, analysisMax: newMax });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/add-analyses/:id', checkAdmin, async (req, res) => {
  try {
    const n = parseInt(req.body.amount) || 10;
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const newMax = (user.analysisMax || 0) + n;
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisMax: newMax } }, {});
    res.json({ success: true, analysisMax: newMax });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/remove-analyses/:id', checkAdmin, async (req, res) => {
  try {
    const n = parseInt(req.body.amount) || 10;
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const newMax = Math.max(0, (user.analysisMax || 0) - n);
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisMax: newMax } }, {});
    res.json({ success: true, analysisMax: newMax });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/kick/:id', checkAdmin, async (req, res) => {
  try { delete activeSessions[req.params.id]; res.json({ success: true }); }
  catch(e) { res.json({ error: e.message }); }
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

app.post('/admin/payment/:id', checkAdmin, async (req, res) => {
  try {
    const { status, plan, note } = req.body;
    const updateData = { paymentStatus: status, paymentNote: note || '' };
    if (status === 'paid') {
      updateData.subscribed = true;
      updateData.plan = plan || 'starter';
      updateData.paymentDate = new Date();
      const analysesMap = { starter: 30, pro: 150, elite: 999999 };
      updateData.analysisMax = analysesMap[plan] || 30;
      updateData.analysisCount = 0;
    } else if (status === 'unpaid') {
      updateData.subscribed = false;
      updateData.plan = 'free';
      updateData.analysisMax = 0;
      delete activeSessions[req.params.id];
    }
    await db.updateAsync({ _id: req.params.id }, { $set: updateData }, {});
    res.json({ success: true });
  } catch(e) { res.json({ error: e.message }); }
});

if (!fs.existsSync(path.join(__dirname, 'uploads'))) fs.mkdirSync(path.join(__dirname, 'uploads'));
app.listen(port, () => console.log('✅ Serveur J4keIA lancé sur http://localhost:' + port));