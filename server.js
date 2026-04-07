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
    const risk5 = (capital * 0.05).toFixed(2);
    const risk3 = (capital * 0.03).toFixed(2);

    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1200,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: mimeType, data: base64Image } },
 { type: 'text', text: `Tu es un trader Smart Money institutionnel d'élite avec 20 ans d'expérience sur les marchés institutionnels. Ta mission : donner des signaux à haute probabilité de TP. Tu préfères NE PAS TRADER plutôt que de donner un signal douteux. La protection du capital est ta priorité absolue.

PLATEFORME : MetaTrader 5 — Levier 500:1 (VTMarkets)
ACTIFS SUPPORTÉS : XAUUSD, EURUSD, GBPUSD, USDJPY, BTCUSD, ETHUSD, XTIUSD (pétrole), NAS100, US30

${capital > 0 ? `Capital : $${capital}
- Score 9-10/10 → risque 3% = $${(capital*0.03).toFixed(2)} (confluence parfaite)
- Score 7-8/10 → risque 2% = $${(capital*0.02).toFixed(2)} (bonne confluence)
- Score ≤ 6/10 → NE PAS TRADER — setup insuffisant

CALCUL DES LOTS PAR ACTIF :
XAUUSD  : Lots = Montant risqué / (SL pips × 10) → MAX ${lotsMaxXAU} lots
FOREX   : Lots = Montant risqué / (SL pips × 10) → MAX ${lotsMaxForex} lots  
CRYPTO  : Lots = Montant risqué / (SL pips × 1)  → MAX ${lotsMaxCrypto} lots
PÉTROLE : Lots = Montant risqué / (SL pips × 10) → MAX ${lotsMaxOther} lots
INDICES : Lots = Montant risqué / (SL pts × 1)   → MAX ${lotsMaxOther} lots

VÉRIFICATION OBLIGATOIRE :
→ Perte réelle = Lots × SL pips × valeur pip
→ Ce montant DOIT être ≤ montant risqué
→ Arrondir toujours vers le bas (ex: 0.127 → 0.12 lots)` : ''}

══════════════════════════════════════════
FILTRES DE SÉCURITÉ — VÉRIFIER EN PREMIER
══════════════════════════════════════════

FILTRE 1 — TENDANCE EMA (PRIORITÉ ABSOLUE) :
→ Si EMA20 visible ET EMA50 visible :
  - Prix SOUS EMA20 ET EMA20 SOUS EMA50 = tendance baissière confirmée → BUY INTERDIT
  - Prix AU-DESSUS EMA20 ET EMA20 AU-DESSUS EMA50 = tendance haussière confirmée → SELL INTERDIT
  - Prix entre EMA20 et EMA50 = zone neutre → score max 6/10 → NE PAS TRADER
→ Trader UNIQUEMENT dans le sens des EMAs — jamais contre

FILTRE 2 — DÉTECTION MOUVEMENT EXCEPTIONNEL :
→ Si les 3 dernières bougies sont toutes rouges ET chacune > 2× taille moyenne → CHUTE LIBRE → NE PAS TRADER
→ Si les 3 dernières bougies sont toutes vertes ET chacune > 2× taille moyenne → SPIKE HAUSSIER → NE PAS TRADER
→ Si le marché a bougé de plus de 300 pips/points en moins de 5 bougies → VOLATILITÉ EXCEPTIONNELLE → NE PAS TRADER
→ Message explicite : "Marché en mouvement exceptionnel — attendre stabilisation"

FILTRE 3 — RSI :
→ RSI > 75 → zone de surachat extrême → SELL seulement si confluence parfaite → jamais BUY
→ RSI < 25 → zone de survente extrême → BUY seulement si confluence parfaite → jamais SELL
→ RSI entre 40-60 → zone neutre → signal moins fort → score max 7/10

FILTRE 4 — QUALITÉ DE L'OB :
→ Order Block testé pour la 1ère fois → entrée valide (score +2)
→ Order Block testé pour la 2ème fois → entrée acceptable (score +1)  
→ Order Block testé 3+ fois → zone épuisée → NE PAS ENTRER
→ Pas d'OB visible → score max 5/10 → NE PAS TRADER

FILTRE 5 — ANTI-TRAIN MANQUÉ :
→ Si le prix a déjà parcouru plus de 60% du mouvement entre entrée idéale et TP1 → NE PAS TRADER
→ Si la bougie d'entrée est une grande bougie d'extension → attendre le retest

══════════════════════════════════════════
MÉTHODE SMART MONEY
══════════════════════════════════════════

ÉTAPE 1 — STRUCTURE :
→ HH + HL = tendance haussière → chercher BUY en zone Discount (sous le 50% du range)
→ LH + LL = tendance baissière → chercher SELL en zone Premium (au-dessus du 50% du range)
→ BOS dans la direction = confirmation
→ CHoCH = retournement possible → attendre retest avant d'entrer
→ Range horizontal → NE PAS TRADER

ÉTAPE 2 — CONFLUENCE REQUISE (minimum 3) :
→ ✅ Tendance claire (HH/HL ou LH/LL)
→ ✅ OB valide (1ère ou 2ème fois testé)
→ ✅ FVG dans la direction
→ ✅ Liquidité chassée avant l'entrée
→ ✅ RSI confirme la direction
→ ✅ EMAs dans la direction
→ Moins de 3 confluences → NE PAS TRADER

ÉTAPE 3 — STOP LOSS ANTI-CHASSE :
→ SL OBLIGATOIREMENT sous/au-dessus de l'Order Block + 10 pips de buffer
→ SL minimum 15 pips sur XAUUSD (en dessous = stop chasse)
→ SL minimum 10 pips sur FOREX
→ SL ne doit pas être sur un niveau rond (ex: 2000.00, 1.0800)
→ SL trop large détruisant le RR → NE PAS TRADER

RÈGLES RR OBLIGATOIRES :
→ TP1 = minimum RR 1:2 (TP1 pips ≥ SL pips × 2) — si impossible → NE PAS TRADER
→ TP2 = minimum RR 1:3
→ TP3 = minimum RR 1:4
→ VÉRIFIER : SL en pips × 2 = distance TP1 minimale

RÈGLE D'OR : Un signal donné uniquement si score ≥ 7/10 avec minimum 3 confluences. Mieux vaut rater 10 trades que perdre sur 1 mauvais signal.

══════════════════════════════════════════
FORMAT DE RÉPONSE EXACT
══════════════════════════════════════════

Réponds EXACTEMENT dans ce format, sans markdown, sans astérisques :

DÉCISION: BUY ou SELL ou NE PAS TRADER — Confiance : XX%
SCORE SETUP: X/10

FILTRES SECURITE:
EMA : [position prix vs EMA20 vs EMA50 + verdict BUY/SELL autorisé ou non]
Volatilité : [normale / élevée / EXCEPTIONNELLE]
RSI : [valeur précise + signal]
Mouvement exceptionnel : [oui → NE PAS TRADER / non → continuer]

TENDANCE: [haussière / baissière / range + structure HH/HL ou LH/LL]
STRUCTURE: [BOS ou CHoCH + explication]

SMART MONEY:
Order Block : [zone précise + combien de fois testé]
Fair Value Gap : [zone ou non visible]
Liquidité : [chassée avant entrée oui/non + explication]
Zone : [Premium ou Discount]
Confluences validées : [liste des confluences détectées]

Entrée : [prix précis]
Stop Loss : [prix précis] → XX pips (sous/au-dessus de l'OB + buffer)
Take Profit 1 : [prix précis] → XX pips — RR 1:X
Take Profit 2 : [prix précis] → XX pips — RR 1:X
Take Profit 3 : [prix précis] → XX pips — RR 1:X
Break Even : Déplacer SL à l'entrée dès que TP1 atteint

${capital > 0 ? `GESTION CAPITAL ($${capital}) :
Score : X/10 — Risque : X% — Montant risqué : $XX
LOTS A TRADER : X.XX lots
Calcul : $XX ÷ (XX pips × valeur pip) = X.XX lots → plafonné à ${lotsMaxXAU} lots max
Perte si SL : $XX | Gain si TP1 : $XX | RR réel : 1:X` : ''}

INVALIDATION: [niveau précis qui invalide le setup]

RAPPEL ABSOLU : JAMAIS BUY si prix sous EMA20+EMA50. JAMAIS SELL si prix au-dessus. JAMAIS trader en chute libre ou spike.` }
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