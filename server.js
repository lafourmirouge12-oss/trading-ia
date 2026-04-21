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
const uploadMulti = multer({ dest: 'uploads/' });
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
const analysesDb = new Datastore({ filename: path.join(__dirname, 'analyses.db'), autoload: true });
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

function isPaiementEnRetard(user) {
  if (user.role === 'admin') return false;
  if (!user.subscribed) return false;
  if (!user.paidUntil) return true;
  return new Date() > new Date(user.paidUntil);
}

function canAnalyze(user) {
  if (user.role === 'admin') return true;
  if (isPaiementEnRetard(user)) return false;
  if (user.subscribed) return true;
  if (typeof user.analysisMax === 'number') return user.analysisCount < user.analysisMax;
  return user.analysisCount < 2;
}

function analysesRestantes(user) {
  if (user.role === 'admin' || user.subscribed) return undefined;
  if (typeof user.analysisMax === 'number') return Math.max(0, user.analysisMax - (user.analysisCount || 0));
  return Math.max(0, 2 - (user.analysisCount || 0));
}

function calculerLots(capital, risquePct, slPips, instrument) {
  if (!capital || !slPips || slPips <= 0) return null;
  const montantRisque = capital * risquePct / 100;
  const inst = (instrument || '').toUpperCase();
  let valeurPipParLot;
  if (inst.includes('XAU') || inst.includes('GOLD')) {
    valeurPipParLot = 100;
  } else if (inst.includes('XAG') || inst.includes('SILVER')) {
    valeurPipParLot = 50;
  } else if (inst.includes('JPY')) {
    valeurPipParLot = 9.09;
  } else if (inst.includes('NAS') || inst.includes('NDX') || inst.includes('US100')) {
    valeurPipParLot = 1;
  } else if (inst.includes('SPX') || inst.includes('SP500') || inst.includes('US500')) {
    valeurPipParLot = 1;
  } else {
    valeurPipParLot = 10;
  }
  const lots = montantRisque / (slPips * valeurPipParLot);
  return Math.max(0.01, Math.round(lots * 100) / 100);
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
      await db.insertAsync({ email: a.email, password: hash, role: 'admin', isVerified: true, analysisCount: 0, analysisMax: 999999, subscribed: true, banned: false, paymentStatus: 'paid', plan: 'admin', createdAt: new Date() });
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
      analysisMax: 2, subscribed: false,
      banned: false, paymentStatus: 'pending',
      plan: 'free', createdAt: new Date()
    });
    const verifyUrl = BASE_URL + '/verify/' + token;
    try {
      await transporter.sendMail({
        from: '"AI-Mazza" <' + process.env.BREVO_SENDER + '>',
        to: email,
        subject: '✅ Confirmez votre compte AI-Mazza',
        html: `<div style="background:#020510;font-family:Arial;padding:40px;color:#fff;max-width:500px;margin:auto;border:1px solid #00f5ff;border-radius:4px;">
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
    if (user.isVerified) return res.json({ error: 'Compte déjà vérifié, connectez-vous !' });
    const token = uuidv4();
    await db.updateAsync({ email: email.toLowerCase() }, { $set: { verifyToken: token } }, {});
    const verifyUrl = BASE_URL + '/verify/' + token;
    await transporter.sendMail({
      from: '"AI-Mazza" <' + process.env.BREVO_SENDER + '>',
      to: email,
      subject: '✅ Nouveau lien de confirmation — AI-Mazza',
      html: `<div style="background:#020510;font-family:Arial;padding:40px;color:#fff;max-width:500px;margin:auto;border:1px solid #00f5ff;border-radius:4px;">
        <h1 style="color:#00f5ff;letter-spacing:4px;font-size:20px;">AI-MAZZA</h1>
        <div style="height:1px;background:#00f5ff;margin:16px 0 24px;opacity:0.3;"></div>
        <a href="${verifyUrl}" style="display:inline-block;background:#00f5ff;color:#020510;padding:14px 32px;text-decoration:none;font-weight:bold;margin:8px 0;border-radius:2px;letter-spacing:2px;font-size:13px;">CONFIRMER MON COMPTE</a>
        <p style="color:rgba(255,255,255,0.3);font-size:11px;margin-top:24px;">Lien valide 24h.</p>
      </div>`
    });
    res.json({ success: 'Email renvoyé ! Vérifiez votre boîte mail.' });
  } catch(e) { res.json({ error: 'Erreur envoi email: ' + e.message }); }
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
    if (user.banned) { req.session.destroy(); return res.status(403).json({ error: 'banned' }); }
    if (!activeSessions[user._id]) {
      activeSessions[user._id] = req.session.sessionId || uuidv4();
      req.session.sessionId = activeSessions[user._id];
    } else if (activeSessions[user._id] !== req.session.sessionId) {
      req.session.destroy();
      return res.status(401).json({ error: 'session_conflict' });
    }
  }
  res.json({
    email: user.email, role: user.role,
    analysisCount: user.analysisCount,
    analysisMax: user.analysisMax,
    subscribed: user.subscribed,
    paiementEnRetard: isPaiementEnRetard(user),
    paidUntil: user.paidUntil || null
  });
});

app.get('/my-analyses', checkAuth, async (req, res) => {
  try {
    const analyses = await analysesDb.findAsync({ userId: req.session.userId });
    analyses.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json(analyses.slice(0, 20));
  } catch(e) { res.json([]); }
});

app.post('/analyses/:id/feedback', checkAuth, async (req, res) => {
  try {
    const { result } = req.body;
    await analysesDb.updateAsync(
      { _id: req.params.id, userId: req.session.userId },
      { $set: { feedbackResult: result } },
      {}
    );
    res.json({ success: true });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/analyze', checkAuth, uploadMulti.fields([
  { name: 'imageH1',  maxCount: 1 },
  { name: 'imageM30', maxCount: 1 },
  { name: 'imageM15', maxCount: 1 },
  { name: 'imageM5',  maxCount: 1 },
  { name: 'imageM1',  maxCount: 1 }
]), async (req, res) => {
  const files = req.files || {};
  const allFiles = [files.imageH1?.[0], files.imageM30?.[0], files.imageM15?.[0], files.imageM5?.[0], files.imageM1?.[0]].filter(Boolean);

  try {
    const user = await db.findOneAsync({ _id: req.session.userId });
    if (!user) return res.status(401).json({ error: 'Non connecté' });
    if (user.banned) {
      allFiles.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });
      return res.status(403).json({ error: 'Compte banni' });
    }
    if (user.role !== 'admin') {
      if (activeSessions[user._id] && activeSessions[user._id] !== req.session.sessionId) {
        allFiles.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });
        req.session.destroy();
        return res.status(401).json({ error: 'session_conflict' });
      }
      if (isPaiementEnRetard(user)) {
        allFiles.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });
        return res.json({ error: 'paiement_en_retard', message: '⚠️ Impayé — Veuillez régler la somme.' });
      }
      if (!canAnalyze(user)) {
        allFiles.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });
        return res.json({ limitReached: true, redirect: '/abonnement.html' });
      }
    }

    if (allFiles.length === 0) return res.status(400).json({ error: 'Aucune image reçue' });

    const capital = parseFloat(req.body.capital) || 0;
    const content = [];
    const tfNames = { imageH1: 'H1', imageM30: 'M30', imageM15: 'M15', imageM5: 'M5', imageM1: 'M1' };
    const tfOrder = ['imageH1', 'imageM30', 'imageM15', 'imageM5', 'imageM1'];

    for (const tfKey of tfOrder) {
      const file = files[tfKey]?.[0];
      if (file) {
        const imageData = fs.readFileSync(file.path);
        content.push({
          type: 'image',
          source: { type: 'base64', media_type: file.mimetype || 'image/png', data: imageData.toString('base64') }
        });
        content.push({ type: 'text', text: `[Graphique ${tfNames[tfKey]}]` });
      }
    }

    const tfDisponibles = tfOrder.filter(k => files[k]?.[0]).map(k => tfNames[k]).join(', ');
    const nbTF = allFiles.length;
    const hasH1 = !!files.imageH1?.[0];
    const hasM5 = !!files.imageM5?.[0];
    const bonusTF = [hasH1 ? 'H1' : null, hasM5 ? 'M5' : null].filter(Boolean).join(', ');

    content.push({
      type: 'text',
      text: `Tu es un trader Smart Money ICT professionnel avec 15 ans d'expérience.${capital ? ` Capital du trader: $${capital}.` : ''}

Tu as reçu ${nbTF} graphique(s) : ${tfDisponibles}.${bonusTF ? `
TIMEFRAMES BONUS FOURNIS: ${bonusTF} — utilise-les pour affiner l'analyse top-down et le CRT.` : ''}
Analyse selon la méthode ICT Smart Money avec intégration CRT (Candle Range Theory).
${hasH1 ? '- H1 fourni : utilise-le comme tendance macro principale pour le top-down' : '- H1 non fourni : déduis la tendance macro depuis M30'}
${hasM5 ? '- M5 fourni : utilise-le pour affiner l'entrée précise et confirmer le FVG' : '- M5 non fourni : utilise M15 ou M1 pour l'entrée'}

RÈGLES D'ANALYSE:
- Analyse la tendance, la structure de marché, les Order Blocks et FVG sur les graphiques fournis
- Avec M30 seul : donne un signal basé sur la tendance principale et les zones clés
- Avec plusieurs TF : analyse en top-down et vérifie la confluence
- NE PAS TRADER uniquement si le marché est vraiment en range sans direction ou si le risque est trop élevé
- Un graphique avec une tendance claire doit donner BUY ou SELL — sois direct et décisif

DÉTECTION CRT (Candle Range Theory):
- Identifier le range asiatique sur M30 : bougies formées entre 20h00 et 08h00 (heure Paris)
- Le range asiatique = zone de consolidation entre le HIGH et le LOW de cette session
- CRT valide = le prix est en train de casser ou vient de casser ce range
- BUY CRT : cassure du HIGH du range asiatique vers le haut
- SELL CRT : cassure du LOW du range asiatique vers le bas
- Si CRT non aligné avec le signal → réduire le score de 1 point et mentionner l'invalidité
- Si CRT aligné → bonus de +1 point sur le score et signaler la confluence

DÉTECTION DE MANIPULATION:
- Identifier les zones de liquidité dangereuses proches du SL
- Sur XAU/USD: SL minimum 15 pips de l'entrée
- Avertir si chasse aux stops probable

Réponds UNIQUEMENT avec un JSON valide, sans texte avant ou après, sans backticks:

{
  "decision": "BUY" ou "SELL" ou "NE PAS TRADER",
  "confiance": "XX%",
  "score": <0 à 10>,
  "tendance": "<tendance principale M30>",
  "tendanceH1": "<H1 ou 'Non fourni'>",
  "tendanceM15": "<M15 ou 'Non fourni'>",
  "tendanceM5": "<M5 ou 'Non fourni'>",
  "tendanceM1": "<M1 ou 'Non fourni'>",
  "confluence": "<alignement TF>",
  "entree": "<prix d'entrée précis>",
  "sl": "<stop loss — min 15 pips sur XAU/USD>",
  "slPips": <pips SL — min 15 sur XAU/USD>,
  "tp1": "<TP1>",
  "tp1Pips": <slPips × 2>,
  "tp2": "<TP2>",
  "tp2Pips": <slPips × 3>,
  "tp3": "<TP3>",
  "tp3Pips": <slPips × 4>,
  "crt": "OUI" ou "NON" ou "NEUTRE",
  "crtDetail": "<explication CRT: range asiatique détecté, cassure confirmée ou non, impact sur le signal>",
  "rangeHaut": "<prix du HIGH du range asiatique si détecté, sinon 'Non détecté'>",
  "rangeBas": "<prix du LOW du range asiatique si détecté, sinon 'Non détecté'>",
  "manipulation": "OUI" ou "NON",
  "manipulationDetail": "<détail manipulation ou 'Aucune'>",
  "ob": "<order block>",
  "fvg": "<fair value gap>",
  "liquidite": "<zones liquidité>",
  "confluences": "<confluences SMC>",
  "invalidation": "<invalidation du setup>",
  "instrument": "<ex: XAUUSD, EURUSD, NAS100>",
  "risquePct": ${capital ? '<1 si score<6, 2 si score 6-7, 3 si score>=8>' : 'null'},
  "montantRisque": ${capital ? `<$${capital} × risquePct / 100>` : 'null'},
  "capital": ${capital || 0}
}

RÈGLES ABSOLUES:
- BUY: SL sous l'entrée, TP au dessus
- SELL: SL au dessus, TP en dessous
- TP1=RR 1:2, TP2=RR 1:3, TP3=RR 1:4
- score 8-10=excellent, 6-7=moyen, 0-5=NE PAS TRADER
- Chiffres précis, décision claire`
    });

    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1500,
      messages: [{ role: 'user', content }]
    });

    allFiles.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });

    let parsed;
    try {
      const text = response.content[0].text.trim();
      const clean = text.replace(/```json|```/g, '').trim();
      const jsonMatch = clean.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error('Pas de JSON trouvé');
      parsed = JSON.parse(jsonMatch[0]);
    } catch(e) {
      return res.status(500).json({ error: 'Erreur parsing IA: ' + e.message });
    }

    // ─── FORCER RR ET DIRECTION CÔTÉ SERVEUR ─────────────────
    if (parsed.entree && parsed.sl && parsed.decision !== 'NE PAS TRADER') {
      const entree = parseFloat(parsed.entree);
      const sl = parseFloat(parsed.sl);
      const isBuy = parsed.decision === 'BUY';
      if (entree && sl) {
        const dist = Math.abs(entree - sl);
        const slCorrige = isBuy ? entree - dist : entree + dist;
        const tp1 = isBuy ? entree + dist * 2 : entree - dist * 2;
        const tp2 = isBuy ? entree + dist * 3 : entree - dist * 3;
        const tp3 = isBuy ? entree + dist * 4 : entree - dist * 4;
        parsed.sl = slCorrige.toFixed(2);
        parsed.tp1 = tp1.toFixed(2);
        parsed.tp2 = tp2.toFixed(2);
        parsed.tp3 = tp3.toFixed(2);
        parsed.slPips = Math.round(dist * 10) / 10;
        parsed.tp1Pips = Math.round(dist * 2 * 10) / 10;
        parsed.tp2Pips = Math.round(dist * 3 * 10) / 10;
        parsed.tp3Pips = Math.round(dist * 4 * 10) / 10;
      }
    }

    // ─── CALCUL LOTS CÔTÉ SERVEUR (garanti) ──────────────────
    if (capital && parsed.slPips && parsed.decision !== 'NE PAS TRADER') {
      const score = parsed.score || 0;
      const risquePct = score >= 8 ? 3 : score >= 6 ? 2 : 1;
      parsed.risquePct = risquePct;
      parsed.lots = calculerLots(capital, risquePct, parsed.slPips, parsed.instrument || '');
      parsed.montantRisque = (capital * risquePct / 100).toFixed(2);
    }

    const analysisId = uuidv4();

    await analysesDb.insertAsync({
      _id: analysisId,
      userId: req.session.userId,
      decision: parsed.decision,
      entry: parsed.entree,
      sl: parsed.sl,
      tp: parsed.tp1,
      tp2: parsed.tp2,
      tp3: parsed.tp3,
      score: parsed.score,
      instrument: parsed.instrument,
      lots: parsed.lots,
      manipulation: parsed.manipulation,
      crt: parsed.crt,
      rangeHaut: parsed.rangeHaut,
      rangeBas: parsed.rangeBas,
      feedbackResult: null,
      createdAt: new Date()
    });

    if (user.role !== 'admin') await db.updateAsync({ _id: user._id }, { $inc: { analysisCount: 1 } }, {});
    const analysesLeft = analysesRestantes(user);

    res.json({ ...parsed, analysesLeft, analysisId });

  } catch (err) {
    allFiles.forEach(f => { try { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); } catch(e){} });
    res.status(500).json({ error: 'Erreur: ' + err.message });
  }
});

app.get('/admin/users', checkAdmin, async (req, res) => {
  try {
    const users = await db.findAsync({ role: { $ne: 'admin' } });
    res.json(users.map(u => ({
      _id: u._id, email: u.email, role: u.role,
      isVerified: u.isVerified,
      analysisCount: u.analysisCount || 0,
      analysisMax: typeof u.analysisMax === 'number' ? u.analysisMax : 2,
      subscribed: u.subscribed,
      banned: u.banned || false,
      paymentStatus: u.paymentStatus || 'pending',
      paymentNote: u.paymentNote || '',
      plan: u.plan || 'free',
      paidUntil: u.paidUntil || null,
      paiementEnRetard: isPaiementEnRetard(u),
      createdAt: u.createdAt,
      online: !!activeSessions[u._id]
    })));
  } catch(e) { res.json({ error: e.message }); }
});

app.get('/admin/stats', checkAdmin, async (req, res) => {
  try {
    const users = await db.findAsync({ role: { $ne: 'admin' } });
    res.json({
      total: users.length,
      verified: users.filter(u => u.isVerified).length,
      paid: users.filter(u => u.paymentStatus === 'paid').length,
      pending: users.filter(u => u.paymentStatus === 'pending').length,
      banned: users.filter(u => u.banned).length,
      enRetard: users.filter(u => isPaiementEnRetard(u)).length,
      online: Object.keys(activeSessions).length
    });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/payment/:id', checkAdmin, async (req, res) => {
  try {
    const { status, plan, note } = req.body;
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const subscribed = status === 'paid';
    let analysisMax = 2;
    if (subscribed) {
      if (plan === 'starter') analysisMax = 30;
      else if (plan === 'premium') analysisMax = 150;
      else if (plan === 'elite') analysisMax = 300;
      else analysisMax = 30;
    }
    let paidUntil = null;
    if (subscribed) {
      const now = new Date();
      const nextSunday = new Date(now);
      const day = now.getDay();
      const daysUntilSunday = day === 0 ? 7 : 7 - day;
      nextSunday.setDate(now.getDate() + daysUntilSunday);
      nextSunday.setHours(23, 59, 59, 999);
      paidUntil = nextSunday.toISOString();
    }
    await db.updateAsync({ _id: req.params.id }, {
      $set: { paymentStatus: status, plan: subscribed ? plan : 'free', paymentNote: note || '', subscribed, analysisMax, analysisCount: 0, paidUntil }
    }, {});
    res.json({ success: true, paidUntil, analysisMax });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/add-one/:id', checkAdmin, async (req, res) => {
  try {
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const current = typeof user.analysisMax === 'number' ? user.analysisMax : 2;
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisMax: current + 1 } }, {});
    res.json({ success: true, analysisMax: current + 1 });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/remove-one/:id', checkAdmin, async (req, res) => {
  try {
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const current = typeof user.analysisMax === 'number' ? user.analysisMax : 2;
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisMax: Math.max(0, current - 1) } }, {});
    res.json({ success: true, analysisMax: Math.max(0, current - 1) });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/add-analyses/:id', checkAdmin, async (req, res) => {
  try {
    const n = parseInt(req.body.amount) || 10;
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const current = typeof user.analysisMax === 'number' ? user.analysisMax : 2;
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisMax: current + n } }, {});
    res.json({ success: true, analysisMax: current + n });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/remove-analyses/:id', checkAdmin, async (req, res) => {
  try {
    const n = parseInt(req.body.amount) || 10;
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const current = typeof user.analysisMax === 'number' ? user.analysisMax : 2;
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisMax: Math.max(0, current - n) } }, {});
    res.json({ success: true, analysisMax: Math.max(0, current - n) });
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
    await db.updateAsync({ _id: req.params.id }, { $set: { analysisMax: 0, subscribed: false } }, {});
    res.json({ success: true });
  } catch(e) { res.json({ error: e.message }); }
});

app.post('/admin/kick/:id', checkAdmin, async (req, res) => {
  try {
    delete activeSessions[req.params.id];
    res.json({ success: true });
  } catch(e) { res.json({ error: e.message }); }
});

if (!fs.existsSync(path.join(__dirname, 'uploads'))) fs.mkdirSync(path.join(__dirname, 'uploads'));

app.listen(port, () => {
  console.log('✅ Serveur lancé sur http://localhost:' + port);
});