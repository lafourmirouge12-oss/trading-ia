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
const analysesDb = new Datastore({ filename: path.join(__dirname, 'analyses.db'), autoload: true });
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

// ─── HISTORIQUE ANALYSES ──────────────────────────────────────────
app.get('/my-analyses', checkAuth, async (req, res) => {
  try {
    const analyses = await analysesDb.findAsync({ userId: req.session.userId }).sort({ createdAt: -1 }).limit(10);
    res.json(analyses);
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/analyses/:id/feedback', checkAuth, async (req, res) => {
  try {
    const { result } = req.body;
    await analysesDb.updateAsync({ _id: req.params.id, userId: req.session.userId }, { $set: { feedbackResult: result, feedbackAt: new Date() } }, {});

    // Sauvegarder aussi dans feedbacks
    const analysis = await analysesDb.findOneAsync({ _id: req.params.id });
    if (analysis) {
      await db.insertAsync({
        type: 'feedback',
        userId: req.session.userId,
        email: analysis.email,
        result,
        capital: analysis.capital,
        decision: analysis.decision,
        entry: analysis.entry,
        sl: analysis.sl,
        tp: analysis.tp,
        createdAt: new Date()
      });
    }
    res.json({ success: true });
  } catch(e) { res.json({ error: e.message }); }
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

    const lotsMaxXAU    = capital <= 300  ? 0.02 : capital <= 500  ? 0.03 : capital <= 1000 ? 0.05 : capital <= 2000 ? 0.10 : capital <= 5000 ? 0.20 : 0.50;
    const lotsMaxForex  = capital <= 300  ? 0.05 : capital <= 500  ? 0.10 : capital <= 1000 ? 0.20 : capital <= 2000 ? 0.50 : 1.00;
    const lotsMaxCrypto = capital <= 300  ? 0.01 : capital <= 500  ? 0.02 : capital <= 1000 ? 0.05 : capital <= 2000 ? 0.10 : 0.20;
    const lotsMaxOther  = capital <= 300  ? 0.05 : capital <= 500  ? 0.10 : capital <= 1000 ? 0.20 : 0.50;

    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1200,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: mimeType, data: base64Image } },
          { type: 'text', text: `Tu es un trader Smart Money institutionnel d'élite avec 20 ans d'expérience. Ta PRIORITÉ ABSOLUE est de PROTÉGER le capital du trader. Tu analyses comme les meilleures banques au monde.

INFORMATIONS COMPTE VTMARKETS :
- Levier : 500:1
- Plateforme : MetaTrader 5

${capital > 0 ? `Capital du trader : $${capital}

RÈGLE DU RISQUE ADAPTÉ :
- Score 8-10/10 : risque 5% = $${(capital*0.05).toFixed(2)}
- Score 5-7/10 : risque 3% = $${(capital*0.03).toFixed(2)}
- Score 1-4/10 : NE PAS TRADER

LIMITES DE LOTS OBLIGATOIRES :
- XAUUSD : MAXIMUM ${lotsMaxXAU} lots
- FOREX   : MAXIMUM ${lotsMaxForex} lots
- CRYPTO  : MAXIMUM ${lotsMaxCrypto} lots
- AUTRES  : MAXIMUM ${lotsMaxOther} lots

FORMULES :
XAUUSD : Lots = Montant risqué / (SL en points × 0.1) — plafonné à ${lotsMaxXAU} lots
FOREX  : Lots = Montant risqué / (SL en pips × 10) — plafonné à ${lotsMaxForex} lots
CRYPTO : Lots = Montant risqué / (SL en points × 1) — plafonné à ${lotsMaxCrypto} lots` : ''}

═══════════════════════════════════════
RÈGLES DE SÉCURITÉ ABSOLUES
═══════════════════════════════════════

RÈGLE 1 — INTERDICTION DE TRADER CONTRE LA TENDANCE :
- Si EMA 20 < EMA 50 ET prix < EMA 20 → INTERDICTION ABSOLUE de BUY
- Si EMA 20 > EMA 50 ET prix > EMA 20 → INTERDICTION ABSOLUE de SELL
- Toujours trader DANS le sens des EMAs

RÈGLE 2 — DÉTECTION DE CHUTE LIBRE / SPIKE :
- Si 3+ bougies consécutives grandes dans le même sens → MARCHÉ EN MOUVEMENT EXCEPTIONNEL → NE PAS TRADER
- Si le marché a bougé de plus de 200 pips en 3 bougies → NE PAS TRADER
- En cas de volatilité extrême → NE PAS TRADER

RÈGLE 3 — RSI :
- RSI > 70 → jamais de BUY
- RSI < 30 → jamais de SELL
- RSI entre 45-55 → neutre → score max 5/10

RÈGLE 4 — CONFLUENCE OBLIGATOIRE :
- Minimum 2 confluences Smart Money sinon NE PAS TRADER
- Sans Order Block visible → NE PAS TRADER

RÈGLE 5 — RR :
- RR minimum 1:2 sur TP1 sinon NE PAS TRADER
- TP2 minimum RR 1:3 — TP3 minimum RR 1:4

═══════════════════════════════════════
MÉTHODOLOGIE SMART MONEY
═══════════════════════════════════════

1. SÉCURITÉ : EMAs position + volatilité + RSI
2. STRUCTURE : HH/HL/LH/LL + BOS ou CHOCH
3. ZONES : Order Block + FVG + Premium/Discount
4. LIQUIDITÉ : BSL/SSL chassée
5. CONFLUENCE : score final

Réponds EXACTEMENT dans ce format sans markdown sans astérisques :

DÉCISION: BUY ou SELL ou NE PAS TRADER — Confiance : XX%
SCORE SETUP: X/10

ANALYSE SÉCURITÉ:
EMAs : [position EMA20 vs EMA50 vs prix]
Volatilité : [normale / élevée / extrême]
RSI : [valeur + signal]
Verdict : [SAFE / DANGEREUX]

STRUCTURE: [HH/HL ou LH/LL — BOS ou CHOCH]

SMART MONEY:
Order Block : [zone ou aucun]
Fair Value Gap : [zone ou aucun]
Liquidité : [BSL/SSL chassée ou non]
Zone : [Premium ou Discount]

Entrée : [prix précis]
Stop Loss : [prix précis] (XX pips)
Take Profit 1 : [prix précis] (XX pips) — RR 1:2
Take Profit 2 : [prix précis] (XX pips) — RR 1:3
Take Profit 3 : [prix précis] (XX pips) — RR 1:4
Break Even : Déplacer SL à l'entrée dès que TP1 atteint

CONFLUENCE: [résumé]

${capital > 0 ? `GESTION CAPITAL ($${capital}) — Levier 500:1 :
Score : X/10 — Risque : X% — Montant : $XX
LOTS A TRADER : X.XX lots
Marge : $XX` : ''}

INVALIDATION: [niveau précis]

JAMAIS BUY si prix sous EMAs — JAMAIS SELL si prix au-dessus EMAs — JAMAIS trader en chute libre` }
        ]
      }]
    });

    fs.unlinkSync(req.file.path);

    const resultText = response.content[0].text;

    // Extraire les données clés de l'analyse
    const entryMatch = resultText.match(/Entr[eé][e]?\s*:\s*([^\n]+)/i);
    const slMatch = resultText.match(/Stop Loss\s*:\s*([^\n(]+)/i);
    const tpMatch = resultText.match(/Take Profit 1\s*:\s*([^\n(]+)/i);
    const decisionMatch = resultText.match(/DÉCISION\s*:\s*([^\n]+)/i);

    const entry = entryMatch ? entryMatch[1].replace(/\*+/g,'').trim().substring(0,20) : '—';
    const sl = slMatch ? slMatch[1].replace(/\*+/g,'').trim().substring(0,20) : '—';
    const tp = tpMatch ? tpMatch[1].replace(/\*+/g,'').trim().substring(0,20) : '—';
    const decision = decisionMatch ? decisionMatch[1].trim().substring(0,30) : '—';

    // Sauvegarder l'analyse en base
    const savedAnalysis = await analysesDb.insertAsync({
      userId: req.session.userId,
      email: user.email,
      result: resultText,
      capital,
      decision,
      entry,
      sl,
      tp,
      feedbackResult: null,
      createdAt: new Date()
    });

    if (user.role !== 'admin') {
      await db.updateAsync({ _id: user._id }, { $inc: { analysisCount: 1 } }, {});
    }

    const analysisMax = user.role === 'admin' ? 999999 : (user.analysisMax || 0);
    const newCount = user.role === 'admin' ? 0 : (user.analysisCount || 0) + 1;
    const newLeft = user.role === 'admin' ? 999999 : Math.max(0, analysisMax - newCount);

    res.json({ result: resultText, analysesLeft: newLeft, capital, analysisId: savedAnalysis._id });
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