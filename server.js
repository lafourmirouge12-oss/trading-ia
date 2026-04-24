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

  // ─── DETECTION INSTRUMENT + NORMALISATION DU SL ─────────────────
  // Le SL recu peut etre en differentes unites selon comment l'IA l'interprete.
  // On convertit tout en "valeur en dollars du mouvement complet du SL" pour 1 lot.
  let valeurMouvementParLot; // = combien $ je perds/gagne pour le SL complet sur 1 lot
  let slEnDollars; // SL converti en dollars (mouvement de prix)

  if (inst.includes('XAU') || inst.includes('GOLD')) {
    // Pour XAUUSD : 1 lot = 100 onces. 1$ de mouvement = 100$ de P&L par lot.
    // L'IA peut renvoyer le SL en :
    //   - dollars (ex: 5 = SL a $5 du prix) ← le plus courant
    //   - pips broker (ex: 50 = $5, 1 pip = $0.10)
    //   - points (ex: 500 = $5, 1 point = $0.01)
    // On detecte intelligemment :
    if (slPips < 30) {
      // < 30 → c'est probablement deja en dollars (SL XAUUSD typique : $1-20)
      slEnDollars = slPips;
    } else if (slPips < 300) {
      // 30-300 → c'est probablement en pips (1 pip = $0.10)
      slEnDollars = slPips / 10;
    } else {
      // >= 300 → c'est en points (1 point = $0.01)
      slEnDollars = slPips / 100;
    }
    valeurMouvementParLot = 100; // 1$ de mouvement = $100 par lot complet
  } else if (inst.includes('XAG') || inst.includes('SILVER')) {
    slEnDollars = slPips < 5 ? slPips : slPips / 10;
    valeurMouvementParLot = 50;
  } else if (inst.includes('JPY')) {
    // Forex JPY : 1 pip = 0.01, 1 lot = ~$9 par pip
    slEnDollars = slPips * 0.01;
    valeurMouvementParLot = 909; // ~$9.09 par pip * 100 pips/dollar
  } else if (inst.includes('NAS') || inst.includes('NDX') || inst.includes('US100')) {
    slEnDollars = slPips;
    valeurMouvementParLot = 1;
  } else if (inst.includes('SPX') || inst.includes('SP500') || inst.includes('US500')) {
    slEnDollars = slPips;
    valeurMouvementParLot = 1;
  } else {
    // Forex standard : 1 pip = 0.0001, 1 lot = ~$10 par pip
    slEnDollars = slPips * 0.0001;
    valeurMouvementParLot = 100000; // 100k unites par lot
  }

  // ─── CALCUL DU LOT ──────────────────────────────────────────────
  // Lot = Risque max / (mouvement SL × valeur par lot)
  const perteParLotComplet = slEnDollars * valeurMouvementParLot;
  let lots = montantRisque / perteParLotComplet;

  // Arrondi a 2 decimales (precision broker standard)
  lots = Math.round(lots * 100) / 100;

  // ─── PROTECTION : lot minimum coherent selon capital ──────────
  // Si le calcul donne moins que ce qui est utile pour ce capital → ajuste
  // Pour XAUUSD, le minimum utile :
  //   - capital < $300 → 0.01 (tres petit compte)
  //   - capital $300-1000 → 0.02 minimum (sinon profits ridicules)
  //   - capital $1000-3000 → 0.03 minimum
  //   - capital > $3000 → 0.05 minimum
  if (inst.includes('XAU') || inst.includes('GOLD')) {
    let lotMinimum;
    if (capital < 300) lotMinimum = 0.01;
    else if (capital < 1000) lotMinimum = 0.02;
    else if (capital < 3000) lotMinimum = 0.03;
    else lotMinimum = 0.05;
    if (lots < lotMinimum) {
      console.log('[LOTS] Calcul: ' + lots + ' → ajuste a ' + lotMinimum + ' (capital $' + capital + ')');
      lots = lotMinimum;
    }
  }

  // ─── PLAFOND DE SECURITE : ne jamais risquer plus de 5% du capital ──
  // Si le lot calcule fait risquer trop, on cap
  const perteReelleEstimee = lots * perteParLotComplet;
  const maxRisqueAbsolu = capital * 0.05; // jamais plus de 5%
  if (perteReelleEstimee > maxRisqueAbsolu) {
    const lotsCappés = maxRisqueAbsolu / perteParLotComplet;
    lots = Math.max(0.01, Math.round(lotsCappés * 100) / 100);
    console.log('[LOTS] Cap securite : risque ' + perteReelleEstimee.toFixed(2) + '$ > 5% capital → lot reduit a ' + lots);
  }

  return Math.max(0.01, lots);
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
    const hasM15 = !!files.imageM15?.[0];
    const hasM1 = !!files.imageM1?.[0];
    const bonusTF = [hasH1 ? 'H1' : null, hasM5 ? 'M5' : null].filter(Boolean).join(', ');

    // ANALYSE CRT KASPER ACTIVEE seulement si M15 + M1 sont fournis
    const crtKasperActif = hasM15 && hasM1;

    content.push({
      type: 'text',
      text: `Tu es un trader Smart Money ICT professionnel avec 15 ans d'expérience.${capital ? ` Capital du trader: $${capital}.` : ''}

Tu as reçu ${nbTF} graphique(s) : ${tfDisponibles}.${bonusTF ? `
TIMEFRAMES BONUS FOURNIS: ${bonusTF} — utilise-les pour affiner l'analyse top-down et le CRT.` : ''}
Analyse selon la méthode ICT Smart Money avec intégration CRT (Candle Range Theory).
${hasH1 ? '- H1 fourni : utilise-le comme tendance macro principale pour le top-down' : '- H1 non fourni : déduis la tendance macro depuis M30'}
${hasM5 ? '- M5 fourni : utilise-le pour affiner l\'entree precise et confirmer le FVG' : '- M5 non fourni : utilise M15 ou M1 pour l\'entree'}

RÈGLES D'ANALYSE:
- Analyse la tendance, la structure de marché, les Order Blocks et FVG sur les graphiques fournis
- Avec M30 seul : donne un signal basé sur la tendance principale et les zones clés
- Avec plusieurs TF : analyse en top-down et vérifie la confluence
- NE PAS TRADER uniquement si le marché est vraiment en range sans direction ou si le risque est trop élevé
- Un graphique avec une tendance claire doit donner BUY ou SELL — sois direct et décisif

DÉTECTION CRT (Candle Range Theory) — RANGE ASIATIQUE:
- Identifier le range asiatique sur M30 : bougies formées entre 20h00 et 08h00 (heure Paris)
- Le range asiatique = zone de consolidation entre le HIGH et le LOW de cette session
- CRT valide = le prix est en train de casser ou vient de casser ce range
- BUY CRT : cassure du HIGH du range asiatique vers le haut
- SELL CRT : cassure du LOW du range asiatique vers le bas
- Si CRT non aligné avec le signal → réduire le score de 1 point et mentionner l'invalidité
- Si CRT aligné → bonus de +1 point sur le score et signaler la confluence
${crtKasperActif ? `
═══════════════════════════════════════════════════════════════
🎯 ANALYSE CRT KASPER KARL ACTIVÉE (M15 + M1 fournis)
═══════════════════════════════════════════════════════════════
EN PLUS de l'analyse ICT classique ci-dessus, applique LA MÉTHODE KASPER KARL
UNIQUEMENT sur les 3 dernières bougies du M15 (jamais M1 ni M30).

⚠️ RÈGLE CRITIQUE : Le pattern CRT Kasper ne se détecte QUE sur M15.
NE JAMAIS extrapoler un "mini CRT" vu sur M1 ou M5 comme un pattern valide.
Si aucun pattern Kasper clair sur M15 → crtKasper = "NON_DETECTE".

PATTERN CRT KASPER (3 dernières bougies M15 UNIQUEMENT) :
• Bougie 1 (KEY CANDLE) : bougie de référence avec un HIGH et un LOW clairs
• Bougie 2 (MANIPULATION/SWEEP) :
   - Sa MÈCHE dépasse un extrême de la bougie 1 (sweep de liquidité)
   - MAIS son CORPS (close) ferme DANS le range de la bougie 1 (fausse cassure)
• Bougie 3 (DISTRIBUTION/BREAK) :
   - Ferme au-delà de l'extrême OPPOSÉ de la bougie 1 = CONFIRMATION
   - DOIT avoir un corps significatif (pas une doji) dans la direction du break

CRT BULLISH = Bougie 2 sweep le LOW + Bougie 3 close NETTEMENT au-dessus du HIGH
CRT BEARISH = Bougie 2 sweep le HIGH + Bougie 3 close NETTEMENT en-dessous du LOW

⚠️ CRT SOFT accepté en plus du STRICT :
- Bougie 3 petite mais ferme de l'autre côté → CRT SOFT valide (+1 score)
- CRT STRICT = break net et clair → +2 score
- CRT SOFT = effleure mais ferme de l'autre côté → +1 score

UTILISATION DU M1 (entrée précise CRT) :
- Une fois le pattern CRT détecté sur M15, regarde le M1 pour le timing d'entrée
- Cherche un retest du niveau cassé (high/low de la key candle M15)
- Le SL doit être placé JUSTE AU-DELÀ du sweep de la bougie 2 M15 (pas plus loin)
  → Exemple BUY : SL = low de bougie 2 M15 - buffer
  → Exemple SELL : SL = high de bougie 2 M15 + buffer

INTÉGRATION INTELLIGENTE CRT KASPER + ICT + STRUCTURE M30 :

⚠️ STRUCTURE M30 — guide mais ne bloque pas :
- M30 dans la direction → bonus +1 point
- M30 contre → -1 point (pas de blocage total)
- Si CRT Kasper détecté → on trade même si M30 légèrement contre

⚠️ REBOND FAIBLE — prudence mais pas de blocage :
- Rebond faible sans CRT → réduire score de 1
- CRT Kasper détecté sur un rebond → signal valide quand même

ARBRE DE DÉCISION :
1. CRT + ICT + M30 alignés → SETUP A+ (score 9-10)
2. CRT + ICT + M30 neutre → bon setup (score 7-8)
3. CRT + ICT + M30 contre → score 6-7, trade quand même
4. CRT seul (sans ICT confirmation) → score 5, trade avec prudence (signal limite)
5. ICT seul sans CRT → score 6-7 si structure claire
6. Ni CRT ni ICT → NE PAS TRADER (score < 5)

PRIORITÉ POUR LE PLACEMENT (entrée + SL) :
- SI CRT Kasper détecté → utiliser les niveaux CRT pour l'entrée et le SL
  (SL plus serré et précis, évite les SL "au feeling" qui se font taper)
- SINON → utiliser les niveaux ICT classiques (OB, FVG, structure)
═══════════════════════════════════════════════════════════════` : ''}

⚠️ VÉRIFICATION RAPIDE :
1. Tendance M30 dans le sens ? → si non : -1 point
2. Zone Discount/Premium respectée ? → si non : -1 point
3. Setup CRT ou ICT détecté ? → si non ET score < 5 → NE PAS TRADER
Blocker seulement si score final < 5 ET aucun pattern clair.


🎯 ═══════════════════════════════════════════════════════════════
ENTRÉE SNIPER OBLIGATOIRE — JAMAIS D'ENTRÉE AU MARCHÉ
═══════════════════════════════════════════════════════════════
Tu es un SNIPER, pas un mitrailleur. L'entrée doit être CHIRURGICALE.

⚠️ CONTEXTE CLIENT : Le trader place TOUJOURS des ordres LIMIT.
L'entrée que tu donnes doit donc être un NIVEAU RÉALISTE que le prix
atteindra probablement. Ton job c'est de choisir le MEILLEUR niveau
possible, pas "un niveau pas loin du prix actuel".

❌ INTERDIT — ne JAMAIS faire :
- Donner un prix "presque comme le prix actuel" pour que ça touche vite
- Choisir un niveau sans signification technique juste parce qu'il est proche
- Donner une entrée en plein milieu d'une zone (ni support ni résistance)
- "Market order" au prix du moment

✅ OBLIGATOIRE — toujours faire :
Le prix d'entrée DOIT coïncider avec un NIVEAU TECHNIQUE MAJEUR
visible clairement sur les graphiques :

POUR UN BUY — l'entrée doit être sur :
• Retest de la KEY CANDLE (high de bougie 1 CRT) ← préféré si CRT détecté
• Retest d'un Order Block haussier clair (bas d'une bougie impulsive haussière visible)
• Retest d'un FVG haussier identifiable (gap entre 3 bougies)
• Retest d'un breakout de structure (ancien high devenu support)
• Retest d'une EMA ou MA significative (20, 50, 200)
• Support horizontal testé plusieurs fois (visible par des mèches à ce niveau)

POUR UN SELL — l'entrée doit être sur :
• Retest de la KEY CANDLE (low de bougie 1 CRT)
• Retest d'un Order Block baissier clair
• Retest d'un FVG baissier
• Retest d'un breakout baissier (ancien low devenu résistance)
• Retest d'une EMA ou MA significative
• Résistance horizontale testée plusieurs fois

⚠️ TEST DE VALIDATION DU NIVEAU D'ENTRÉE :
Avant de valider le niveau d'entrée X, pose-toi ces 2 questions :
1. Est-ce que je peux EXPLIQUER pourquoi le prix devrait réagir PILE à ce niveau ?
2. Est-ce que ce niveau est VISIBLE clairement sur au moins 2 timeframes ?
Si tu ne peux pas répondre OUI aux 2 → le niveau est trop faible, CHOISIS EN UN AUTRE
ou "NE PAS TRADER" si aucun niveau valable n'existe.

RÈGLES CHIFFRÉES :
- Le prix d'entrée DOIT être à au moins 0.1% (environ 5$ pour XAUUSD à 4700) du prix actuel
- Sauf exception : si le prix est LITTÉRALEMENT sur un niveau technique clé à l'instant T
- Dans ce cas, le mentionner explicitement dans le champ "entreeType"

COMMENT CALCULER L'ENTRÉE :
1. Identifie TOUS les niveaux techniques visibles sur les graphiques
2. Pour BUY : trouve le support le plus PROCHE ET LE PLUS FORT en-dessous du prix
3. Pour SELL : trouve la résistance la plus PROCHE ET LA PLUS FORTE au-dessus
4. Le meilleur niveau = celui qui a été testé PLUSIEURS FOIS ou qui a une confluence
   (ex: OB + FVG + EMA qui se croisent au même endroit)
5. Place l'entrée PILE sur ce niveau (ordre LIMIT)
6. Si aucun niveau FORT mais CRT détecté → utiliser les niveaux CRT comme référence

VALIDITÉ DE L'ENTRÉE :
- L'entrée doit rester valide MAX 2 heures (bougies M15 évoluent vite)
- Si le prix s'éloigne trop du niveau d'entrée → signal expiré
- L'IA doit indiquer si l'entrée est "immédiate" (prix déjà au niveau) ou "en attente"

SL DOIT ÊTRE EXTRÊMEMENT SERRÉ :
- BUY : SL juste sous le low de la zone d'entrée (OB, key candle, etc.) - 2-3$ buffer max
- SELL : SL juste au-dessus du high de la zone - 2-3$ buffer max
- Avec entrée sniper, SL typique XAUUSD = 3-8$ (vs 10-15$ en entrée marché)
- R:R cible minimum 1:3, idéal 1:4 ou 1:5
═══════════════════════════════════════════════════════════════


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
  "entree": "<prix d'entrée précis — DOIT être sur un niveau technique, PAS au marché>",
  "entreeType": "<LIMIT ou MARKET>",
  "entreeLevel": "<description du niveau: 'Retest OB H1 à 4675', 'Key candle M15 low', 'FVG M30 haussier', etc.>",
  "entreeStatut": "<IMMEDIATE si prix déjà au niveau, EN_ATTENTE si le prix doit revenir>",
  "sl": "<stop loss — min 15 pips sur XAU/USD${crtKasperActif ? ', mais si CRT Kasper détecté: SL = juste au-delà du sweep bougie 2' : ''}>",
  "slPips": <pips SL — min 15 sur XAU/USD>,
  "tp1": "<TP1>",
  "tp1Pips": <slPips × 2>,
  "tp2": "<TP2>",
  "tp2Pips": <slPips × 3>,
  "tp3": "<TP3>",
  "tp3Pips": <slPips × 4>,
  "crt": "OUI" ou "NON" ou "NEUTRE",
  "crtDetail": "<explication CRT: range asiatique détecté, cassure confirmée ou non, impact sur le signal>",
  ${crtKasperActif ? `"crtKasper": "DETECTE_BULLISH" ou "DETECTE_BEARISH" ou "NON_DETECTE",
  "crtKasperDetail": "<si détecté: décris le pattern 3 bougies M15 - key candle / sweep / break, et précise comment ça affine l'entrée et le SL>",
  "crtKasperImpact": "<impact sur le placement final: SL plus serré, entrée plus précise, etc.>",` : ''}
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