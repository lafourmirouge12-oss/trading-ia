require('dotenv').config();
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const Datastore = require('@seald-io/nedb');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

// ─── METAAPI POUR CONNEXION MT5 ────────────────────────────────────
let MetaApi = null;
try {
  MetaApi = require('metaapi.cloud-sdk').default;
} catch(e) {
  console.warn('[MetaApi] SDK non installé. Run: npm install metaapi.cloud-sdk');
}
const metaApi = (MetaApi && process.env.METAAPI_TOKEN)
  ? new MetaApi(process.env.METAAPI_TOKEN)
  : null;

// ═══════════════════════════════════════════════════════════════════
// 🛡️ WATCHDOG MetaApi — undeploy auto après 5 min max
// ═══════════════════════════════════════════════════════════════════
// Stocke chaque deploy avec timestamp pour forcer l'undeploy si oublié
// Évite que MetaApi facture en arrière-plan en cas de crash/bug

const deployTracker = {}; // { accountId: { deployedAt: ms, login: string } }
const MAX_DEPLOY_MS = 5 * 60 * 1000; // 5 minutes max

// Marquer un compte comme deployé
function trackDeploy(accountId, login) {
  if (!accountId) return;
  deployTracker[accountId] = {
    deployedAt: Date.now(),
    login: login || 'unknown'
  };
  console.log('[WATCHDOG] Deploy tracked: ' + accountId + ' (' + login + ')');
}

// Marquer un compte comme undeployé (le retire du tracker)
function trackUndeploy(accountId) {
  if (deployTracker[accountId]) {
    const elapsed = Math.round((Date.now() - deployTracker[accountId].deployedAt) / 1000);
    console.log('[WATCHDOG] Undeploy tracked: ' + accountId + ' (apres ' + elapsed + 's)');
    delete deployTracker[accountId];
  }
}

// Watchdog principal : verifie toutes les 60s qu'aucun compte n'est deployé > 5 min
async function watchdogCheck() {
  if (!metaApi) return;
  const now = Date.now();
  const expired = Object.entries(deployTracker).filter(
    ([id, data]) => (now - data.deployedAt) > MAX_DEPLOY_MS
  );

  if (expired.length === 0) return;

  console.log('[WATCHDOG] ' + expired.length + ' compte(s) deployes > 5 min → undeploy force');

  for (const [accountId, data] of expired) {
    try {
      const account = await metaApi.metatraderAccountApi.getAccount(accountId);
      if (account && account.state !== 'UNDEPLOYED') {
        await account.undeploy();
        console.log('[WATCHDOG] ✅ Undeploy force pour ' + accountId + ' (login ' + data.login + ')');
      }
    } catch (err) {
      console.log('[WATCHDOG] Erreur undeploy ' + accountId + ':', err.message);
    } finally {
      delete deployTracker[accountId];
    }
  }
}

// Scan au demarrage : trouve tous les comptes encore deployés et les arrete
// (au cas ou le serveur a redemarre sans avoir fait undeploy)
async function watchdogBootScan() {
  if (!metaApi) return;
  console.log('[WATCHDOG] Boot scan en cours...');
  try {
    const accountsApi = metaApi.metatraderAccountApi;
    let allAccounts = [];

    // Chercher tous les comptes (avec pagination si dispo)
    if (typeof accountsApi.getAccountsWithInfiniteScrollPagination === 'function') {
      let page = 0;
      while (page < 50) {
        try {
          const resp = await accountsApi.getAccountsWithInfiniteScrollPagination({
            limit: 100, offset: page * 100
          });
          const items = resp.items || resp || [];
          if (items.length === 0) break;
          allAccounts.push(...items);
          if (items.length < 100) break;
          page++;
        } catch(e) { break; }
      }
    } else if (typeof accountsApi.getAccounts === 'function') {
      allAccounts = await accountsApi.getAccounts({});
    }

    // Filtrer ceux qui sont deployes (utilise par AI-Mazza, ID commence par 'AIM-')
    const aimDeployed = allAccounts.filter(a =>
      String(a.name || '').startsWith('AIM-') &&
      a.state !== 'UNDEPLOYED'
    );

    if (aimDeployed.length > 0) {
      console.log('[WATCHDOG] Boot: ' + aimDeployed.length + ' compte(s) AIM trouves deployes → undeploy');
      for (const acc of aimDeployed) {
        try {
          await acc.undeploy();
          console.log('[WATCHDOG] Boot undeploy: ' + acc.login);
        } catch(e) {}
      }
    } else {
      console.log('[WATCHDOG] Boot: aucun compte AIM deploye, tout est propre ✅');
    }
  } catch(err) {
    console.log('[WATCHDOG] Boot scan erreur:', err.message);
  }
}

// Lancer le watchdog toutes les 60 secondes
if (metaApi) {
  setInterval(watchdogCheck, 60 * 1000);
  // Boot scan apres 30s (laisse le temps au serveur de se stabiliser)
  setTimeout(watchdogBootScan, 30 * 1000);
}

// ─── CHIFFREMENT AES-256 POUR CREDENTIALS MT5 ───────────────────────
// La cle est dans MT5_ENCRYPT_KEY (32 chars) — DOIT etre dans .env / Render
const ENCRYPT_KEY = (process.env.MT5_ENCRYPT_KEY || '').padEnd(32, '0').slice(0, 32);
const IV_LENGTH = 16;

function encryptStr(text) {
  if (!text) return null;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPT_KEY), iv);
  let encrypted = cipher.update(String(text), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptStr(payload) {
  if (!payload || typeof payload !== 'string' || !payload.includes(':')) return null;
  try {
    const [ivHex, encryptedHex] = payload.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPT_KEY), iv);
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch(e) {
    console.error('[CRYPTO] Erreur dechiffrement:', e.message);
    return null;
  }
}

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
const leconsDb = new Datastore({ filename: path.join(__dirname, 'lecons.db'), autoload: true });
const setupsGagnantsDb = new Datastore({ filename: path.join(__dirname, 'setups-gagnants.db'), autoload: true });
const positionsTrackingDb = new Datastore({ filename: path.join(__dirname, 'positions-tracking.db'), autoload: true });
const notificationsDb = new Datastore({ filename: path.join(__dirname, 'notifications.db'), autoload: true });
const activeSessions = {};

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('trust proxy', 1); // Render est derrière un proxy
app.use(session({
  store: new FileStore({
    path: path.join(__dirname, 'sessions'),
    ttl: 30 * 24 * 60 * 60,
    retries: 0,
    reapInterval: 24 * 60 * 60
  }),
  secret: process.env.SESSION_SECRET || 'ai-mazza-secret-2024',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
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

// ─── ANTI-PIÈGE RANGE ASIATIQUE ─────────────────────────────────────
// Évite d'acheter dans le top 20% du range asiatique ou de vendre dans
// le bottom 20% (zones de chasse de stops avant cassure de London/NY)
function verifierPiegeRangeAsiatique(parsed) {
  if (!parsed.rangeHaut || !parsed.rangeBas || parsed.decision === 'NE PAS TRADER') return parsed;

  const haut = parseFloat(parsed.rangeHaut);
  const bas = parseFloat(parsed.rangeBas);
  const entree = parseFloat(parsed.entree);
  if (isNaN(haut) || isNaN(bas) || isNaN(entree) || haut <= bas) return parsed;

  const zone = (haut - bas) * 0.20;
  const piegeBuy = parsed.decision === 'BUY' && entree >= haut - zone && entree <= haut;
  const piegeSell = parsed.decision === 'SELL' && entree <= bas + zone && entree >= bas;

  if (piegeBuy || piegeSell) {
    console.log('[ANTI-PIEGE] Entree ' + entree + ' dans zone piege range [' + bas + '-' + haut + ']');
    parsed.decision = 'NE PAS TRADER';
    parsed.score = 3;
    parsed.piegeRangeAlerte = 'Entree dans zone de chasse de stops du range asiatique';
  }

  return parsed;
}

// ═══════════════════════════════════════════════════════════════════
// 🛡️ PROTECTIONS AVANCÉES (RSI extrême + mouvement épuisé + distance TP)
// ═══════════════════════════════════════════════════════════════════

// Calcul du RSI 14 sur un tableau de bougies (closes uniquement)
function calculerRSI(candles, periode = 14) {
  if (!candles || candles.length < periode + 1) return null;
  const closes = candles.slice(-(periode + 1)).map(c => c.close);
  let gains = 0, pertes = 0;
  for (let i = 1; i < closes.length; i++) {
    const diff = closes[i] - closes[i - 1];
    if (diff > 0) gains += diff;
    else pertes += Math.abs(diff);
  }
  if (pertes === 0) return 100;
  if (gains === 0) return 0;
  const rs = (gains / periode) / (pertes / periode);
  return +(100 - (100 / (1 + rs))).toFixed(1);
}

// Calcul Moving Average simple sur les N dernières clôtures
function calculerMA(candles, periode) {
  if (!candles || candles.length < periode) return null;
  const closes = candles.slice(-periode).map(c => c.close);
  return +(closes.reduce((a, b) => a + b, 0) / periode).toFixed(2);
}

// ═══════════════════════════════════════════════════════════════════
// 📊 INDICATEURS TECHNIQUES — INJECTION DANS LE PROMPT
// ═══════════════════════════════════════════════════════════════════
// Calcule RSI + MA20 + MA50 sur H1, M15, M5 et formatte un bloc texte
// que l'IA reçoit AVANT de proposer son trade. Comme ça elle voit les
// indicateurs réels (pas devinés sur les screens) et propose un setup
// cohérent avec eux.
async function getBlocIndicateursTechniques(userId, symbole) {
  if (!metaApi) return '';
  try {
    const user = await db.findOneAsync({ _id: userId });
    if (!user || !user.mt5 || !user.mt5.metaApiAccountId) return '';

    const account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
    if (account.state !== 'DEPLOYED') return '';
    const connection = account.getRPCConnection();
    await connection.connect();
    await connection.waitSynchronized();

    const sym = (symbole || 'XAUUSD').toUpperCase();
    const suffixes = ['', '-VIP', '-STD', '-ECN', '-PRO', '-Raw', '.a', '_m', '-micro'];

    let candlesH1 = [], candlesM15 = [], candlesM5 = [], prixActuel = null;

    for (const sfx of suffixes) {
      try {
        const symFull = sym + sfx;
        candlesH1 = await connection.getHistoricalCandles(symFull, '1h', undefined, 60) || [];
        candlesM15 = await connection.getHistoricalCandles(symFull, '15m', undefined, 60) || [];
        candlesM5 = await connection.getHistoricalCandles(symFull, '5m', undefined, 60) || [];
        const tick = await connection.getSymbolPrice(symFull);
        if (tick && tick.bid) prixActuel = (tick.bid + tick.ask) / 2;
        if (candlesH1.length && candlesM15.length) break;
      } catch(e) {}
    }
    if (!candlesM15.length) return '';

    // Calcul des indicateurs
    const indic = {
      h1: {
        rsi: calculerRSI(candlesH1, 14),
        ma20: calculerMA(candlesH1, 20),
        ma50: calculerMA(candlesH1, 50)
      },
      m15: {
        rsi: calculerRSI(candlesM15, 14),
        ma20: calculerMA(candlesM15, 20),
        ma50: calculerMA(candlesM15, 50)
      },
      m5: {
        rsi: calculerRSI(candlesM5, 14),
        ma20: calculerMA(candlesM5, 20),
        ma50: calculerMA(candlesM5, 50)
      }
    };

    // Helper pour formater RSI avec alerte
    const fmtRSI = (rsi) => {
      if (rsi === null) return '—';
      if (rsi >= 80) return `${rsi} ⚠ SURACHAT EXTRÊME`;
      if (rsi <= 20) return `${rsi} ⚠ SURVENTE EXTRÊME`;
      if (rsi >= 70) return `${rsi} ⚠ surachat`;
      if (rsi <= 30) return `${rsi} ⚠ survente`;
      return `${rsi}`;
    };

    // Helper pour position vs MA
    const fmtMA = (ma, prix) => {
      if (ma === null || prix === null) return '—';
      const diff = prix - ma;
      const sign = diff > 0 ? '+' : '';
      return `${ma} (${sign}${diff.toFixed(1)}p ${diff > 0 ? 'au-dessus' : 'sous'})`;
    };

    let txt = '\n═══════════════════════════════════════════════════════════════\n';
    txt += '📊 INDICATEURS TECHNIQUES (calculés sur les vraies bougies du marché)\n';
    txt += '═══════════════════════════════════════════════════════════════\n';
    if (prixActuel) txt += `Prix actuel : ${prixActuel.toFixed(2)}\n\n`;

    txt += `H1  | RSI ${fmtRSI(indic.h1.rsi)} | MA20 ${fmtMA(indic.h1.ma20, prixActuel)} | MA50 ${fmtMA(indic.h1.ma50, prixActuel)}\n`;
    txt += `M15 | RSI ${fmtRSI(indic.m15.rsi)} | MA20 ${fmtMA(indic.m15.ma20, prixActuel)} | MA50 ${fmtMA(indic.m15.ma50, prixActuel)}\n`;
    txt += `M5  | RSI ${fmtRSI(indic.m5.rsi)} | MA20 ${fmtMA(indic.m5.ma20, prixActuel)} | MA50 ${fmtMA(indic.m5.ma50, prixActuel)}\n\n`;

    // Alertes synthétiques
    const alertes = [];
    const rsiExtremesSurvente = [indic.h1.rsi, indic.m15.rsi, indic.m5.rsi].filter(r => r !== null && r <= 25).length;
    const rsiExtremesSurachat = [indic.h1.rsi, indic.m15.rsi, indic.m5.rsi].filter(r => r !== null && r >= 75).length;
    if (rsiExtremesSurvente >= 2) alertes.push('⚠ RSI EN SURVENTE EXTRÊME sur plusieurs timeframes — REBOND TECHNIQUE TRÈS PROBABLE. NE PAS VENDRE sans signal de retournement clair (CHoCH M5 + bougie d\'absorption).');
    if (rsiExtremesSurachat >= 2) alertes.push('⚠ RSI EN SURACHAT EXTRÊME sur plusieurs timeframes — CORRECTION TRÈS PROBABLE. NE PAS ACHETER sans signal de retournement clair.');

    // Position vs MAs (cohérence avec direction)
    if (prixActuel && indic.h1.ma20 && indic.h1.ma50) {
      const sousMA = prixActuel < indic.h1.ma20 && prixActuel < indic.h1.ma50;
      const auDessusMA = prixActuel > indic.h1.ma20 && prixActuel > indic.h1.ma50;
      const distMA20 = Math.abs(prixActuel - indic.h1.ma20);
      const distMA50 = Math.abs(prixActuel - indic.h1.ma50);

      if (sousMA && distMA50 > 50) alertes.push(`⚠ Prix très éloigné SOUS MA50 H1 (${distMA50.toFixed(0)} pips) — mouvement baissier épuisé, rebond probable, éviter SELL agressifs.`);
      if (auDessusMA && distMA50 > 50) alertes.push(`⚠ Prix très éloigné AU-DESSUS MA50 H1 (${distMA50.toFixed(0)} pips) — mouvement haussier épuisé, correction probable, éviter BUY agressifs.`);
    }

    if (alertes.length) {
      txt += 'ALERTES TECHNIQUES :\n';
      alertes.forEach(a => txt += a + '\n');
      txt += '\n';
    }

    txt += 'UTILISE CES VALEURS pour ta décision. Si elles contredisent ton signal initial → revoir ou refuser.\n';
    txt += '═══════════════════════════════════════════════════════════════\n';
    return txt;
  } catch(err) {
    console.log('[INDICATEURS] Erreur:', err.message);
    return '';
  }
}

// Vérifications avancées post-IA. Récupère les bougies M15 + prix actuel
// et applique 3 protections critiques.
async function verifierProtectionsAvancees(parsed, userId) {
  if (parsed.decision !== 'BUY' && parsed.decision !== 'SELL') return parsed;
  if (!metaApi) return parsed;

  try {
    const user = await db.findOneAsync({ _id: userId });
    if (!user || !user.mt5 || !user.mt5.metaApiAccountId) return parsed;

    const account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
    if (account.state !== 'DEPLOYED') return parsed; // pas de deploy ici, économie
    const connection = account.getRPCConnection();
    await connection.connect();
    await connection.waitSynchronized();

    const symbole = (parsed.instrument || 'XAUUSD').toUpperCase();
    const suffixes = ['', '-VIP', '-STD', '-ECN', '-PRO', '-Raw', '.a', '_m', '-micro'];

    let candlesM15 = [], prixActuel = null;
    for (const sfx of suffixes) {
      try {
        const sym = symbole + sfx;
        candlesM15 = await connection.getHistoricalCandles(sym, '15m', undefined, 30) || [];
        const tick = await connection.getSymbolPrice(sym);
        if (tick && tick.bid) prixActuel = (tick.bid + tick.ask) / 2;
        if (candlesM15.length && prixActuel) break;
      } catch(e) {}
    }
    if (!candlesM15.length || !prixActuel) return parsed;

    const isBuy = parsed.decision === 'BUY';
    const entree = parseFloat(parsed.entree);
    const sl = parseFloat(parsed.sl);
    const tp = parseFloat(parsed.tp1);
    const distSL = Math.abs(entree - sl);

    const alertes = [];
    let scoreReduit = false;
    let tradeAnnule = false;

    // ─── PROTECTION 1 : RSI EXTRÊME ───────────────────────────────
    // Évite d'acheter en surachat ou de vendre en survente extrême
    const rsi = calculerRSI(candlesM15, 14);
    if (rsi !== null) {
      if (isBuy && rsi >= 80) {
        tradeAnnule = true;
        alertes.push(`RSI M15 ${rsi} en SURACHAT EXTRÊME — correction probable, BUY annulé`);
      } else if (!isBuy && rsi <= 20) {
        tradeAnnule = true;
        alertes.push(`RSI M15 ${rsi} en SURVENTE EXTRÊME — rebond technique probable, SELL annulé`);
      } else if (isBuy && rsi >= 70) {
        scoreReduit = true;
        alertes.push(`RSI M15 ${rsi} en surachat — risque de correction, score réduit`);
      } else if (!isBuy && rsi <= 30) {
        scoreReduit = true;
        alertes.push(`RSI M15 ${rsi} en survente — risque de rebond, score réduit`);
      }
    }

    // ─── PROTECTION 2 : ANTI-CHASSE DE MOUVEMENT ÉPUISÉ ──────────
    // Logique corrigée : on regarde les 5 dernières bougies M15.
    // Si l'une d'elles a un range > 3.5× la moyenne ET va dans le même sens
    // que notre trade (= mouvement violent déjà fait, on chasse), on annule
    // ou on réduit selon la sévérité. Trader CONTRE un mouvement violent
    // récent = aussi annulé (risque énorme).
    if (candlesM15.length >= 20) {
      const ranges = candlesM15.slice(-20, -5).map(c => c.high - c.low); // moyenne sur les 15 précédentes (hors les 5 récentes)
      const rangeMoyen = ranges.reduce((a, b) => a + b, 0) / ranges.length;

      const cinqDernieres = candlesM15.slice(-5);
      let plusGrosseRecente = null;
      let plusGrosRatio = 0;

      for (const c of cinqDernieres) {
        const r = c.high - c.low;
        const ratio = rangeMoyen > 0 ? r / rangeMoyen : 1;
        if (ratio > plusGrosRatio) {
          plusGrosRatio = ratio;
          plusGrosseRecente = c;
        }
      }

      if (plusGrosseRecente && plusGrosRatio >= 3.5) {
        const corps = plusGrosseRecente.close - plusGrosseRecente.open;
        const haussiere = corps > 0;
        const baissiere = corps < 0;

        // Cas 1 : trade DANS le sens du mouvement violent récent = chasse de prix
        const memeSens = (isBuy && haussiere) || (!isBuy && baissiere);
        // Cas 2 : trade CONTRE le mouvement violent = très risqué aussi
        const contreSens = (isBuy && baissiere) || (!isBuy && haussiere);

        if (memeSens) {
          tradeAnnule = true;
          alertes.push(`Bougie M15 récente ${plusGrosRatio.toFixed(1)}× la moyenne dans le sens — tu chasses un mouvement déjà fait, trade annulé`);
        } else if (contreSens && plusGrosRatio >= 4) {
          tradeAnnule = true;
          alertes.push(`Bougie M15 récente ${plusGrosRatio.toFixed(1)}× la moyenne contre direction — trop risqué, trade annulé`);
        } else if (contreSens) {
          scoreReduit = true;
          alertes.push(`Bougie M15 récente ${plusGrosRatio.toFixed(1)}× la moyenne contre direction — score réduit`);
        }
      } else if (plusGrosseRecente && plusGrosRatio >= 2.5) {
        // Mouvement modéré récent : on garde mais on flag
        const corps = plusGrosseRecente.close - plusGrosseRecente.open;
        const memeSens = (isBuy && corps > 0) || (!isBuy && corps < 0);
        if (memeSens) {
          scoreReduit = true;
          alertes.push(`Mouvement récent ${plusGrosRatio.toFixed(1)}× la moyenne dans le sens — risque épuisement, score réduit`);
        }
      }
    }

    // ─── PROTECTION 3 : R:R RÉEL DEPUIS LE PRIX ACTUEL ────────────
    // C'est le R:R réel après slippage / si le LIMIT s'exécute mal.
    // Seuil : 1.3 minimum pour passer (équilibré : ni strict ni laxiste).
    const distPrixVersTP = Math.abs(prixActuel - tp);
    const distPrixVersSL = Math.abs(prixActuel - sl);
    const rrReel = distPrixVersSL > 0 ? distPrixVersTP / distPrixVersSL : 0;

    if (rrReel < 1) {
      tradeAnnule = true;
      alertes.push(`R:R réel ${rrReel.toFixed(2)} < 1 — depuis prix ${prixActuel.toFixed(2)} : TP ${distPrixVersTP.toFixed(1)}p / SL ${distPrixVersSL.toFixed(1)}p — trade annulé`);
    } else if (rrReel < 1.3) {
      scoreReduit = true;
      alertes.push(`R:R réel ${rrReel.toFixed(2)} faible — depuis prix ${prixActuel.toFixed(2)} : TP ${distPrixVersTP.toFixed(1)}p / SL ${distPrixVersSL.toFixed(1)}p — score réduit`);
    }

    // ─── PROTECTION 4 : DISTANCE ENTRÉE INSUFFISANTE ──────────────
    // Pour XAU, un LIMIT order placé à moins de 8 pips du prix actuel
    // est risqué (slippage, refus broker, fill au pire moment).
    // Seuil adapté selon instrument.
    const symLow = symbole.toLowerCase();
    const seuilDistance = (symLow.includes('xau') || symLow.includes('gold')) ? 8 : 5;
    const distEntreePrix = Math.abs(prixActuel - entree);

    if (distEntreePrix > 0 && distEntreePrix < seuilDistance) {
      // Vérifier si l'entrée est encore "atteignable" dans le bon sens
      const buyLimitOK = isBuy && entree < prixActuel;   // BUY LIMIT = sous le prix
      const sellLimitOK = !isBuy && entree > prixActuel; // SELL LIMIT = au-dessus

      if (buyLimitOK || sellLimitOK) {
        // LIMIT trop proche → risque de fill au mauvais moment
        scoreReduit = true;
        alertes.push(`Entrée LIMIT à seulement ${distEntreePrix.toFixed(1)} pips du prix actuel — risque de fill défavorable, score réduit`);
      }
    }

    // ─── APPLICATION ──────────────────────────────────────────────
    if (alertes.length > 0) {
      parsed.protectionsAlertes = alertes.join(' | ');
      console.log('[PROTECTIONS] ' + parsed.decision + ' ' + symbole + ' : ' + alertes.join(' | '));

      if (tradeAnnule) {
        parsed.decision = 'NE PAS TRADER';
        parsed.score = 3;
      } else if (scoreReduit) {
        parsed.score = Math.min(parsed.score || 5, 5);
      }
    }

    return parsed;
  } catch(err) {
    console.log('[PROTECTIONS] Erreur:', err.message);
    return parsed;
  }
}

// ─── RÉCUPÈRE LE PRIX ACTUEL VIA METAAPI ────────────────────────────
// Utilise le compte MT5 du user pour obtenir le bid/ask en live.
// Retourne null si pas dispo (le réajustement sera skippé).
async function getPrixActuel(userId, symbole) {
  if (!metaApi) return null;
  try {
    const user = await db.findOneAsync({ _id: userId });
    if (!user || !user.mt5 || !user.mt5.metaApiAccountId) return null;

    const account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
    let deployedHere = false;
    if (account.state === 'UNDEPLOYED') {
      await account.deploy();
      trackDeploy(account.id, user.mt5.login);
      deployedHere = true;
      await account.waitConnected();
    }
    const connection = account.getRPCConnection();
    await connection.connect();
    await connection.waitSynchronized();

    // Tester les variantes de symbole (broker peut avoir XAUUSD-VIP, etc.)
    const suffixes = ['', '-VIP', '-STD', '-ECN', '-PRO', '-Raw', '.a', '_m', '-micro'];
    let prix = null;
    for (const sfx of suffixes) {
      try {
        const tick = await connection.getSymbolPrice(symbole + sfx);
        if (tick && tick.bid) { prix = (tick.bid + tick.ask) / 2; break; }
      } catch(e) {}
    }

    if (deployedHere) {
      try { await account.undeploy(); trackUndeploy(account.id); } catch(e) {}
    }
    return prix;
  } catch(err) {
    console.log('[PRIX-ACTUEL] Erreur:', err.message);
    return null;
  }
}

// ─── RÉAJUSTEMENT AUTOMATIQUE DE L'ENTRÉE ───────────────────────────
// Si l'entrée IA n'est plus valide (dépassée ou trop loin du prix actuel),
// la fonction cherche un meilleur niveau dans les données techniques de
// l'analyse (OB, FVG, range, key candle) et replace l'ordre dessus.
// SL/TP sont recalculés automatiquement pour conserver le même R:R.
async function reajusterEntreeSiNecessaire(parsed, userId) {
  if (parsed.decision !== 'BUY' && parsed.decision !== 'SELL') return parsed;
  if (!parsed.entree || !parsed.sl) return parsed;

  const symbole = (parsed.instrument || 'XAUUSD').toUpperCase();
  const prixActuel = await getPrixActuel(userId, symbole);
  if (!prixActuel) {
    console.log('[REAJUST] Prix actuel indisponible, on garde l\'entrée IA');
    return parsed;
  }

  const isBuy = parsed.decision === 'BUY';
  const entreeIA = parseFloat(parsed.entree);
  const slIA = parseFloat(parsed.sl);
  const distSLOriginal = Math.abs(entreeIA - slIA); // on conserve le R:R en gardant cette distance

  // Tolérance : 0.8% du prix pour XAU (~$38 sur 4700), 0.3% pour le reste
  const tolerancePct = symbole.includes('XAU') || symbole.includes('GOLD') ? 0.008 : 0.003;
  const tolerance = prixActuel * tolerancePct;

  // L'entrée est-elle dépassée ?
  // BUY : entrée doit être <= prix actuel (on achète plus bas / au prix). Si entrée > prix → ordre STOP, ok seulement si proche
  // SELL : entrée doit être >= prix actuel
  const entreeDepassee = isBuy ? entreeIA < prixActuel - tolerance : entreeIA > prixActuel + tolerance;
  const entreeTropLoin = Math.abs(entreeIA - prixActuel) > tolerance * 3;

  if (!entreeDepassee && !entreeTropLoin) {
    console.log('[REAJUST] Entrée IA ' + entreeIA + ' valide vs prix actuel ' + prixActuel.toFixed(2));
    return parsed;
  }

  console.log('[REAJUST] Entrée ' + entreeIA + ' invalide (prix actuel ' + prixActuel.toFixed(2) + ') → recherche niveau alternatif');

  // ─── CHERCHER UN NIVEAU ALTERNATIF DANS LE JSON IA ──────────────
  // L'IA renvoie OB, FVG, range, key candle. On extrait tous les chiffres
  // mentionnés et on garde ceux qui sont du bon côté du prix actuel.
  const candidats = [];
  const ajouterCandidat = (val, source) => {
    const n = parseFloat(val);
    if (isNaN(n) || n <= 0) return;
    // BUY : on veut acheter en-dessous du prix actuel → niveau < prix
    // SELL : on veut vendre au-dessus → niveau > prix
    if (isBuy && n < prixActuel - tolerance * 0.3) candidats.push({ prix: n, source });
    if (!isBuy && n > prixActuel + tolerance * 0.3) candidats.push({ prix: n, source });
  };

  // Range asiatique
  if (parsed.rangeBas) ajouterCandidat(parsed.rangeBas, 'Low range asiatique');
  if (parsed.rangeHaut) ajouterCandidat(parsed.rangeHaut, 'High range asiatique');

  // Extraire les nombres des champs textuels (OB, FVG, etc.)
  const champsTexte = [parsed.ob, parsed.fvg, parsed.crtKasperDetail, parsed.entreeLevel, parsed.liquidite, parsed.confluences].filter(Boolean);
  for (const txt of champsTexte) {
    const matches = String(txt).match(/\d{3,5}(?:\.\d+)?/g) || [];
    for (const m of matches) ajouterCandidat(m, 'Niveau technique');
  }

  if (candidats.length === 0) {
    console.log('[REAJUST] Aucun niveau alternatif trouvé → trade annulé');
    parsed.decision = 'NE PAS TRADER';
    parsed.score = Math.min(parsed.score || 5, 4);
    parsed.reajustAlerte = 'Entrée IA dépassée et aucun niveau alternatif identifiable. Trade annulé pour ne pas chasser le prix.';
    return parsed;
  }

  // Choisir le candidat le PLUS PROCHE du prix actuel (= entrée la plus réaliste)
  candidats.sort((a, b) => Math.abs(a.prix - prixActuel) - Math.abs(b.prix - prixActuel));
  const meilleur = candidats[0];

  const nouvelleEntree = meilleur.prix;
  const nouveauSL = isBuy ? nouvelleEntree - distSLOriginal : nouvelleEntree + distSLOriginal;
  const nouveauTP1 = isBuy ? nouvelleEntree + distSLOriginal * 2 : nouvelleEntree - distSLOriginal * 2;
  const nouveauTP2 = isBuy ? nouvelleEntree + distSLOriginal * 3 : nouvelleEntree - distSLOriginal * 3;
  const nouveauTP3 = isBuy ? nouvelleEntree + distSLOriginal * 4 : nouvelleEntree - distSLOriginal * 4;

  parsed.entreeOriginale = parsed.entree;
  parsed.entree = nouvelleEntree.toFixed(2);
  parsed.sl = nouveauSL.toFixed(2);
  parsed.tp1 = nouveauTP1.toFixed(2);
  parsed.tp2 = nouveauTP2.toFixed(2);
  parsed.tp3 = nouveauTP3.toFixed(2);
  parsed.entreeLevel = meilleur.source + ' (réajusté auto)';
  parsed.entreeStatut = 'EN_ATTENTE';
  parsed.reajustAlerte = 'Entrée réajustée : ' + parsed.entreeOriginale + ' → ' + parsed.entree + ' (' + meilleur.source + '). Prix actuel: ' + prixActuel.toFixed(2);

  console.log('[REAJUST] OK : ' + parsed.entreeOriginale + ' → ' + parsed.entree + ' (' + meilleur.source + ')');
  return parsed;
}

// ═══════════════════════════════════════════════════════════════════
// 🔍 DÉTECTION OB / FVG CÔTÉ SERVEUR (algorithmique, gratuit)
// ═══════════════════════════════════════════════════════════════════
// Pas d'IA, juste de l'analyse de bougies. Donne à l'IA des données
// objectives au lieu de la laisser "voir" sur les screens.

function detecterOrderBlocks(candles) {
  // OB bullish = dernière bougie baissière avant un mouvement haussier impulsif
  // OB bearish = dernière bougie haussière avant un mouvement baissier impulsif
  if (!candles || candles.length < 5) return { bullish: [], bearish: [] };

  const obs = { bullish: [], bearish: [] };
  // Calcul du range moyen pour détecter les "mouvements impulsifs"
  const ranges = candles.map(c => Math.abs(c.high - c.low));
  const rangeMoyen = ranges.reduce((a, b) => a + b, 0) / ranges.length;

  for (let i = 1; i < candles.length - 3; i++) {
    const c = candles[i];
    const next3 = candles.slice(i + 1, i + 4);
    const corps = c.close - c.open;
    const rangeCandle = c.high - c.low;

    // Mouvement impulsif après la bougie ?
    const closesNext = next3.map(n => n.close);
    const mouvementHaussier = next3.every(n => n.close > c.high) && (closesNext[2] - c.high) > rangeMoyen * 1.5;
    const mouvementBaissier = next3.every(n => n.close < c.low) && (c.low - closesNext[2]) > rangeMoyen * 1.5;

    // OB bullish = bougie baissière (corps < 0) suivie de mouvement haussier impulsif
    if (corps < 0 && mouvementHaussier) {
      obs.bullish.push({
        zone: { high: c.high, low: c.low },
        time: c.time,
        rangeCandle
      });
    }
    // OB bearish = bougie haussière (corps > 0) suivie de mouvement baissier impulsif
    if (corps > 0 && mouvementBaissier) {
      obs.bearish.push({
        zone: { high: c.high, low: c.low },
        time: c.time,
        rangeCandle
      });
    }
  }
  // Garder seulement les 3 plus récents de chaque type
  obs.bullish = obs.bullish.slice(-3);
  obs.bearish = obs.bearish.slice(-3);
  return obs;
}

function detecterFairValueGaps(candles) {
  // FVG bullish = candle[i].low > candle[i-2].high (gap entre 3 bougies, mouvement haussier)
  // FVG bearish = candle[i].high < candle[i-2].low (gap entre 3 bougies, mouvement baissier)
  if (!candles || candles.length < 3) return { bullish: [], bearish: [] };

  const fvgs = { bullish: [], bearish: [] };
  for (let i = 2; i < candles.length; i++) {
    const c1 = candles[i - 2];
    const c3 = candles[i];

    if (c3.low > c1.high) {
      fvgs.bullish.push({
        zone: { high: c3.low, low: c1.high },
        time: c3.time,
        size: c3.low - c1.high
      });
    }
    if (c3.high < c1.low) {
      fvgs.bearish.push({
        zone: { high: c1.low, low: c3.high },
        time: c3.time,
        size: c1.low - c3.high
      });
    }
  }
  // Garder les 3 plus récents
  fvgs.bullish = fvgs.bullish.slice(-3);
  fvgs.bearish = fvgs.bearish.slice(-3);
  return fvgs;
}

// Récupère les OB/FVG via MetaAPI et formatte pour le prompt
async function getBlocOBFVG(userId, symbole) {
  if (!metaApi) return '';
  try {
    const user = await db.findOneAsync({ _id: userId });
    if (!user || !user.mt5 || !user.mt5.metaApiAccountId) return '';

    const account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
    if (account.state !== 'DEPLOYED') return ''; // pas de deploy ici pour économiser
    const connection = account.getRPCConnection();
    await connection.connect();
    await connection.waitSynchronized();

    // Récupérer 50 bougies M15 et 30 bougies M5
    let candlesM15 = [], candlesM5 = [];
    const suffixes = ['', '-VIP', '-STD', '-ECN', '-PRO', '-Raw', '.a', '_m', '-micro'];
    for (const sfx of suffixes) {
      try {
        const sym = symbole + sfx;
        candlesM15 = await connection.getHistoricalCandles(sym, '15m', undefined, 50) || [];
        candlesM5 = await connection.getHistoricalCandles(sym, '5m', undefined, 30) || [];
        if (candlesM15.length || candlesM5.length) break;
      } catch(e) {}
    }
    if (!candlesM15.length && !candlesM5.length) return '';

    const obM15 = detecterOrderBlocks(candlesM15);
    const fvgM15 = detecterFairValueGaps(candlesM15);
    const obM5 = detecterOrderBlocks(candlesM5);
    const fvgM5 = detecterFairValueGaps(candlesM5);

    let txt = '\n═══════════════════════════════════════════════════════════════\n';
    txt += '🔍 NIVEAUX TECHNIQUES DÉTECTÉS PAR ANALYSE OBJECTIVE DES BOUGIES\n';
    txt += '═══════════════════════════════════════════════════════════════\n';
    txt += '(Calculés algorithmiquement sur les vraies bougies, pas estimés sur les screens)\n\n';

    if (obM15.bullish.length) {
      txt += 'OB BULLISH M15 (zones de demande, prix peut rebondir dessus pour acheter) :\n';
      obM15.bullish.forEach(o => {
        txt += `  - Zone ${o.zone.low.toFixed(2)} - ${o.zone.high.toFixed(2)}\n`;
      });
    }
    if (obM15.bearish.length) {
      txt += 'OB BEARISH M15 (zones d\'offre, prix peut rejeter dessus pour vendre) :\n';
      obM15.bearish.forEach(o => {
        txt += `  - Zone ${o.zone.low.toFixed(2)} - ${o.zone.high.toFixed(2)}\n`;
      });
    }
    if (fvgM15.bullish.length) {
      txt += 'FVG BULLISH M15 (gaps haussiers, magnétiques pour le prix) :\n';
      fvgM15.bullish.forEach(f => {
        txt += `  - Zone ${f.zone.low.toFixed(2)} - ${f.zone.high.toFixed(2)}\n`;
      });
    }
    if (fvgM15.bearish.length) {
      txt += 'FVG BEARISH M15 (gaps baissiers) :\n';
      fvgM15.bearish.forEach(f => {
        txt += `  - Zone ${f.zone.low.toFixed(2)} - ${f.zone.high.toFixed(2)}\n`;
      });
    }
    if (obM5.bullish.length || obM5.bearish.length || fvgM5.bullish.length || fvgM5.bearish.length) {
      txt += '\nM5 (timing fin) :\n';
      [...obM5.bullish, ...obM5.bearish].slice(0, 2).forEach(o => {
        txt += `  - OB M5: ${o.zone.low.toFixed(2)} - ${o.zone.high.toFixed(2)}\n`;
      });
      [...fvgM5.bullish, ...fvgM5.bearish].slice(0, 2).forEach(f => {
        txt += `  - FVG M5: ${f.zone.low.toFixed(2)} - ${f.zone.high.toFixed(2)}\n`;
      });
    }

    txt += '\nUTILISE CES NIVEAUX EN PRIORITÉ pour ton entrée. Ils sont calculés sur les vraies données de marché.\n';
    txt += '═══════════════════════════════════════════════════════════════\n';
    return txt;
  } catch(err) {
    console.log('[OB-FVG] Erreur:', err.message);
    return '';
  }
}

// ═══════════════════════════════════════════════════════════════════
// 🏆 MÉMOIRE DES SETUPS GAGNANTS
// ═══════════════════════════════════════════════════════════════════
// Quand un trade fait +2R ou plus, on extrait ses caractéristiques
// et on les stocke comme "pattern à reproduire".

async function enregistrerSetupGagnant(analyse) {
  if (typeof analyse.tradeProfit !== 'number' || analyse.tradeProfit <= 0) return;
  if (analyse.setupGagnantEnregistre) return;
  try {
    // Calculer le ratio R atteint
    const slDist = analyse.slPips || 0;
    const profit = analyse.tradeProfit;
    const tp1Dist = analyse.tp1Pips || slDist * 2;
    // Approx: si profit > 2× la perte que SL aurait causée → setup gagnant solide
    // On garde les setups qui ont fait > 2R en termes de prix (TP1 atteint au minimum)
    const dateAnalyse = new Date(analyse.createdAt);
    const utcHour = dateAnalyse.getUTCHours();
    let session;
    if (utcHour >= 0 && utcHour < 7) session = 'asian';
    else if (utcHour >= 7 && utcHour < 12) session = 'london';
    else if (utcHour >= 12 && utcHour < 17) session = 'ny';
    else session = 'after-hours';

    await setupsGagnantsDb.insertAsync({
      _id: uuidv4(),
      userId: analyse.userId,
      instrument: analyse.instrument || 'XAUUSD',
      direction: analyse.decision,
      session,
      jourSemaine: dateAnalyse.getUTCDay(),
      score: analyse.score || 0,
      profit,
      crt: analyse.crt || 'NON',
      crtKasper: analyse.crtKasper || null,
      ob: analyse.ob || null,
      fvg: analyse.fvg || null,
      entreeLevel: analyse.entreeLevel || null,
      confluences: analyse.confluences || null,
      createdAt: dateAnalyse,
      enregistreLe: new Date()
    });

    await analysesDb.updateAsync({ _id: analyse._id }, { $set: { setupGagnantEnregistre: true }});
    console.log('[SETUP-GAGNANT] Enregistré pour ' + analyse.instrument + ' ' + analyse.decision + ' (+' + profit + '$)');
  } catch(err) { console.log('[SETUP-GAGNANT] Erreur:', err.message); }
}

async function getBlocSetupsGagnants(userId, instrument) {
  try {
    const setups = await setupsGagnantsDb.findAsync({ userId, instrument: instrument || 'XAUUSD' });
    if (!setups.length) return '';
    setups.sort((a, b) => b.profit - a.profit);
    const top = setups.slice(0, 5);

    let txt = '\n═══════════════════════════════════════════════════════════════\n';
    txt += '🏆 TES MEILLEURS SETUPS PRÉCÉDENTS — PATTERNS À REPRODUIRE\n';
    txt += '═══════════════════════════════════════════════════════════════\n';
    txt += 'Voici les caractéristiques des trades qui ont le mieux marché.\n';
    txt += 'Si le setup actuel ressemble à ceux-ci → boost ta confiance.\n\n';

    const noms = ['dim', 'lun', 'mar', 'mer', 'jeu', 'ven', 'sam'];
    top.forEach((s, i) => {
      txt += `${i + 1}. ${s.direction} ${s.instrument} (${noms[s.jourSemaine]} ${s.session}) — Profit: +${s.profit.toFixed(0)}$, Score initial: ${s.score}/10\n`;
      if (s.crt && s.crt !== 'NON') txt += `   CRT: ${s.crt}\n`;
      if (s.crtKasper) txt += `   CRT Kasper: ${s.crtKasper}\n`;
      if (s.entreeLevel) txt += `   Niveau d'entrée: ${s.entreeLevel}\n`;
    });

    // Stats globales
    const totalProfit = setups.reduce((sum, s) => sum + s.profit, 0);
    const sessionCounts = {};
    setups.forEach(s => { sessionCounts[s.session] = (sessionCounts[s.session] || 0) + 1; });
    const meilleureSession = Object.entries(sessionCounts).sort((a, b) => b[1] - a[1])[0];

    txt += `\nTOTAL : ${setups.length} setups gagnants enregistrés, +${totalProfit.toFixed(0)}$ cumulés.\n`;
    if (meilleureSession) txt += `Session la plus profitable : ${meilleureSession[0]} (${meilleureSession[1]} setups).\n`;
    txt += '═══════════════════════════════════════════════════════════════\n';
    return txt;
  } catch(err) { return ''; }
}

// ═══════════════════════════════════════════════════════════════════
// 📚 POST-MORTEM AUTO (sans screen — récupère les bougies via MetaAPI)
// ═══════════════════════════════════════════════════════════════════

async function getLeconsPourPrompt(userId) {
  try {
    const lecons = await leconsDb.findAsync({ userId });
    lecons.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const top = lecons.slice(0, 10);
    if (!top.length) return '';
    let txt = '\n═══════════════════════════════════════════════════════════════\n';
    txt += '📚 LEÇONS DES TRADES PERDANTS — À RESPECTER\n';
    txt += '═══════════════════════════════════════════════════════════════\n';
    txt += 'Erreurs commises sur des trades précédents qui ont touché le SL.\n';
    txt += 'AVANT de proposer ce nouveau trade, vérifie que tu ne refais PAS la même erreur :\n\n';
    top.forEach((l, i) => {
      txt += `${i + 1}. [${l.setupType || 'Setup'}] ${l.lecon}\n`;
      if (l.signalManque) txt += `   Signal manqué : ${l.signalManque}\n`;
    });
    txt += '═══════════════════════════════════════════════════════════════\n';
    return txt;
  } catch(err) { return ''; }
}

async function genererPostMortemAuto(analyse, userId) {
  if (!metaApi) return null;
  try {
    const user = await db.findOneAsync({ _id: userId });
    if (!user || !user.mt5 || !user.mt5.metaApiAccountId) return null;

    const account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
    if (account.state !== 'DEPLOYED') return null;
    const connection = account.getRPCConnection();
    await connection.connect();
    await connection.waitSynchronized();

    // Récupérer les 30 bougies M5 autour du moment du SL touché
    const symbole = (analyse.instrument || 'XAUUSD').toUpperCase();
    const tempsCloture = new Date(analyse.tradeClotureTemps || analyse.createdAt);
    const debut = new Date(tempsCloture.getTime() - 30 * 5 * 60 * 1000); // 2h30 avant

    let candles = [];
    const suffixes = ['', '-VIP', '-STD', '-ECN', '-PRO', '-Raw', '.a', '_m', '-micro'];
    for (const sfx of suffixes) {
      try {
        candles = await connection.getHistoricalCandles(symbole + sfx, '5m', debut, 30) || [];
        if (candles.length) break;
      } catch(e) {}
    }
    if (!candles.length) return null;

    // Détecter OB/FVG sur ces bougies pour donner du contexte à l'IA
    const obs = detecterOrderBlocks(candles);
    const fvgs = detecterFairValueGaps(candles);

    // Construction du résumé textuel pour l'IA
    const dernieresBougies = candles.slice(-10).map(c => ({
      time: new Date(c.time).toISOString(),
      o: c.open.toFixed(2),
      h: c.high.toFixed(2),
      l: c.low.toFixed(2),
      c: c.close.toFixed(2)
    }));

    const promptText = `Tu es un trader expert ICT. Analyse pourquoi ce trade a touché le SL.

CONTEXTE DU TRADE PERDANT :
- Instrument : ${analyse.instrument || 'XAUUSD'}
- Direction : ${analyse.decision}
- Entrée : ${analyse.entry}
- SL : ${analyse.sl}
- TP1 : ${analyse.tp}
- Score initial : ${analyse.score}/10
- Range asiatique : ${analyse.rangeBas || '?'} - ${analyse.rangeHaut || '?'}
- Perte : ${analyse.tradeProfit}$
- Date analyse : ${new Date(analyse.createdAt).toISOString()}
- Date clôture : ${tempsCloture.toISOString()}

DONNÉES OBJECTIVES DU MARCHÉ AU MOMENT DU SL :
- 10 dernières bougies M5 avant le SL :
${dernieresBougies.map(b => `  ${b.time}: O=${b.o} H=${b.h} L=${b.l} C=${b.c}`).join('\n')}

- OB bullish détectés : ${obs.bullish.length} (zones: ${obs.bullish.map(o => o.zone.low.toFixed(2) + '-' + o.zone.high.toFixed(2)).join(', ') || 'aucun'})
- OB bearish détectés : ${obs.bearish.length} (zones: ${obs.bearish.map(o => o.zone.low.toFixed(2) + '-' + o.zone.high.toFixed(2)).join(', ') || 'aucun'})
- FVG bullish : ${fvgs.bullish.length}, FVG bearish : ${fvgs.bearish.length}

MISSION :
1. Identifie CE QUI A FOIRÉ (qu'est-ce qui a fait que le SL a été touché)
2. Identifie LE SIGNAL qu'il fallait voir avant pour éviter ce trade
3. Formule une LEÇON courte et actionnable

Réponds UNIQUEMENT en JSON valide :
{
  "ce_qui_a_foire": "explication courte (1 phrase)",
  "signal_manque": "le signal à voir avant (1 phrase concrète)",
  "lecon": "règle impérative pour les futures analyses (1 phrase)",
  "setup_type": "type de setup (CRT Kasper / OB+FVG / Range asiatique / etc.)"
}`;

    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 600,
      messages: [{ role: 'user', content: promptText }]
    });

    const raw = response.content[0].text.trim();
    const m = raw.match(/\{[\s\S]*\}/);
    if (!m) return null;
    const leconParsed = JSON.parse(m[0]);

    const leconId = uuidv4();
    await leconsDb.insertAsync({
      _id: leconId,
      userId,
      analyseId: analyse._id,
      instrument: analyse.instrument,
      direction: analyse.decision,
      perte: analyse.tradeProfit,
      ceQuiAFoire: leconParsed.ce_qui_a_foire,
      signalManque: leconParsed.signal_manque,
      lecon: leconParsed.lecon,
      setupType: leconParsed.setup_type,
      auto: true,
      createdAt: new Date()
    });

    await analysesDb.updateAsync({ _id: analyse._id }, { $set: { postMortemStatut: 'auto', leconId }});
    console.log('[POSTMORTEM-AUTO] Leçon générée pour ' + analyse._id);
    return leconParsed;
  } catch(err) {
    console.log('[POSTMORTEM-AUTO] Erreur:', err.message);
    return null;
  }
}

// Surveillance auto : check les trades perdants/gagnants et déclenche post-mortem ou setup gagnant
// ═══════════════════════════════════════════════════════════════════
// 🎯 TP PARTIELS + BREAK-EVEN AUTO
// ═══════════════════════════════════════════════════════════════════
// Pour chaque position ouverte :
// 1. Récupère le TP1 prévu depuis l'analyse stockée
// 2. Si le prix actuel a touché ou dépassé TP1 :
//    → Ferme 50% de la position (profit sécurisé)
//    → Déplace le SL à l'entrée (break-even, plus aucun risque)
// 3. Le reste continue librement vers TP2/TP3 ou se ferme au SL/BE
//
// Tracking via positions-tracking.db (évite de refaire 2x la même action)

// ═══════════════════════════════════════════════════════════════════
// 🔔 NOTIFICATIONS (in-app)
// ═══════════════════════════════════════════════════════════════════
async function creerNotification(userId, type, titre, message, data = {}) {
  try {
    await notificationsDb.insertAsync({
      _id: uuidv4(),
      userId,
      type,        // 'tp_partiel', 'be_auto', 'sl_touche', 'lot_reduit', etc.
      titre,
      message,
      data,
      lue: false,
      createdAt: new Date()
    });
  } catch(err) { console.log('[NOTIF] Erreur création:', err.message); }
}

// ═══════════════════════════════════════════════════════════════════
// 💰 LOT DYNAMIQUE (réduction si drawdown jour)
// ═══════════════════════════════════════════════════════════════════
// Si l'utilisateur a perdu plus de 5% de son capital sur la journée,
// on réduit automatiquement le lot proposé de 50%.
// Calcul basé sur les analyses du jour avec feedback 'sl' ou tradeProfit < 0.

async function getFacteurRisque(userId, capital) {
  if (!capital || capital <= 0) return { facteur: 1, alerte: null };
  try {
    const debutJour = new Date();
    debutJour.setHours(0, 0, 0, 0);

    const analysesJour = await analysesDb.findAsync({
      userId,
      createdAt: { $gte: debutJour }
    });

    // Calculer la perte totale du jour (basée sur tradeProfit ou estimation via SL)
    let perteJour = 0;
    let nbSL = 0;
    for (const a of analysesJour) {
      if (typeof a.tradeProfit === 'number' && a.tradeProfit < 0) {
        perteJour += Math.abs(a.tradeProfit);
        nbSL++;
      } else if (a.feedbackResult === 'sl' && a.lots && a.slPips) {
        // Estimation : pour XAU, 1 lot × $1 de SL ≈ $100
        const slDollars = a.slPips < 30 ? a.slPips : a.slPips / 10;
        const perteEstimee = slDollars * 100 * a.lots;
        perteJour += perteEstimee;
        nbSL++;
      }
    }

    const pertePct = (perteJour / capital) * 100;

    // Règles
    if (pertePct >= 10) {
      return {
        facteur: 0.25,
        alerte: `⚠️ Drawdown jour ${pertePct.toFixed(1)}% — lot réduit de 75% (protection capital)`
      };
    }
    if (pertePct >= 5) {
      return {
        facteur: 0.5,
        alerte: `⚠️ Drawdown jour ${pertePct.toFixed(1)}% — lot réduit de 50% (protection capital)`
      };
    }
    if (nbSL >= 2) {
      return {
        facteur: 0.5,
        alerte: `⚠️ Déjà 2 SL aujourd'hui — lot réduit de 50% (anti-tilt)`
      };
    }
    return { facteur: 1, alerte: null };
  } catch(err) {
    return { facteur: 1, alerte: null };
  }
}

async function gererTpPartielsEtBE() {
  if (!metaApi) return;
  try {
    const users = await db.findAsync({ 'mt5.metaApiAccountId': { $exists: true } });

    for (const user of users) {
      try {
        const account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
        if (account.state !== 'DEPLOYED') continue;
        const connection = account.getRPCConnection();
        await connection.connect();
        await connection.waitSynchronized();

        const positions = await connection.getPositions();
        if (!positions || !positions.length) continue;

        for (const pos of positions) {
          try {
            // Vérifier si on a déjà fait le partiel pour cette position
            const tracking = await positionsTrackingDb.findOneAsync({ positionId: pos.id });
            if (tracking && tracking.tp1Done) continue;

            // Trouver l'analyse correspondante (récupérée par symbole + direction + entry proche)
            const symbAnalyse = pos.symbol.toUpperCase().replace(/-.*/, '').replace(/_.*/, '');
            const direction = pos.type === 'POSITION_TYPE_BUY' ? 'BUY' : 'SELL';
            const dateLimit = new Date(Date.now() - 24 * 60 * 60 * 1000); // dernières 24h

            const analyses = await analysesDb.findAsync({
              userId: user._id,
              decision: direction,
              createdAt: { $gte: dateLimit }
            });

            // Match : entrée proche du openPrice de la position (tolérance 5$)
            let analyseMatch = null;
            for (const a of analyses) {
              const aEntree = parseFloat(a.entree);
              if (Math.abs(aEntree - parseFloat(pos.openPrice)) < 5) {
                if (!analyseMatch || new Date(a.createdAt) > new Date(analyseMatch.createdAt)) {
                  analyseMatch = a;
                }
              }
            }

            if (!analyseMatch || !analyseMatch.tp1) continue;

            const tp1 = parseFloat(analyseMatch.tp1);
            const entree = parseFloat(pos.openPrice);
            const prixActuel = parseFloat(pos.currentPrice);
            const isBuy = direction === 'BUY';

            // Vérifier si TP1 atteint
            const tp1Atteint = isBuy ? prixActuel >= tp1 : prixActuel <= tp1;
            if (!tp1Atteint) continue;

            // 1. Fermer 50% de la position
            const volumeTotal = parseFloat(pos.volume);
            const volumeAFermer = Math.round(volumeTotal * 0.5 * 100) / 100; // arrondi 2 décimales
            const volumeMin = 0.01;
            if (volumeAFermer < volumeMin) {
              console.log('[TP-PARTIEL] Volume trop petit pour fermeture partielle, on skip');
              continue;
            }

            try {
              await connection.closePositionPartially(pos.id, volumeAFermer);
              console.log('[TP-PARTIEL] Fermé ' + volumeAFermer + ' lots sur ' + pos.symbol + ' (TP1 atteint à ' + prixActuel + ')');
            } catch(err) {
              console.log('[TP-PARTIEL] Erreur fermeture:', err.message);
              continue;
            }

            // 2. Attendre 2 secondes pour que la fermeture soit effective
            await new Promise(r => setTimeout(r, 2000));

            // 3. Déplacer le SL à l'entrée (BE) sur les 50% restants
            try {
              const slBE = entree;
              const tpRestant = pos.takeProfit;
              await connection.modifyPosition(pos.id, slBE, tpRestant);
              console.log('[BE-AUTO] SL déplacé à BE (' + slBE + ') sur ' + pos.symbol);
            } catch(err) {
              console.log('[BE-AUTO] Erreur SL→BE:', err.message);
            }

            // 4. Marquer comme traité dans le tracking DB
            await positionsTrackingDb.insertAsync({
              positionId: pos.id,
              symbol: pos.symbol,
              userId: user._id,
              tp1Done: true,
              tp1Time: new Date(),
              entree,
              tp1,
              volumeFerme: volumeAFermer
            });

            // 5. Optionnel : notifier le client (si la fonction existe)
            try {
              if (typeof creerNotification === 'function') {
                await creerNotification(
                  user._id,
                  'tp_partiel',
                  '🎯 TP1 atteint — Profit sécurisé',
                  `${pos.symbol} : 50% fermés à ${prixActuel}, SL déplacé à BE. Le reste continue.`,
                  { symbol: pos.symbol, tp1: prixActuel, volumeFerme: volumeAFermer }
                );
              }
            } catch(e) {}
          } catch(err) {
            if (!err.message.includes('not found')) console.log('[TP-BE] Erreur position:', err.message);
          }
        }
      } catch(err) {
        if (!err.message.includes('not found')) console.log('[TP-BE] Erreur user:', err.message);
      }
    }
  } catch(err) { console.log('[TP-BE] Erreur globale:', err.message); }
}

// Cleanup auto du tracking : supprime les entries vieilles de 7 jours
async function cleanupTracking() {
  try {
    const il_y_a_7j = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    await positionsTrackingDb.removeAsync({ tp1Time: { $lt: il_y_a_7j } }, { multi: true });
  } catch(e) {}
}

// Lancer toutes les 2 minutes (rapide pour pas rater le TP1)
setInterval(gererTpPartielsEtBE, 2 * 60 * 1000);
// Cleanup tous les jours
setInterval(cleanupTracking, 24 * 60 * 60 * 1000);

async function surveillerTradesEtApprendre() {
  if (!metaApi) return;
  try {
    const dateLimit = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const analysesAVerifier = await analysesDb.findAsync({
      createdAt: { $gte: dateLimit },
      decision: { $in: ['BUY', 'SELL'] },
      apprentissageStatut: { $ne: 'TRAITE' }
    });
    if (!analysesAVerifier.length) return;

    const parUser = {};
    for (const a of analysesAVerifier) {
      if (!parUser[a.userId]) parUser[a.userId] = [];
      parUser[a.userId].push(a);
    }

    for (const userId of Object.keys(parUser)) {
      try {
        const user = await db.findOneAsync({ _id: userId });
        if (!user || !user.mt5 || !user.mt5.metaApiAccountId) continue;

        const account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
        if (account.state !== 'DEPLOYED') continue;
        const connection = account.getRPCConnection();
        await connection.connect();
        await connection.waitSynchronized();

        const deals = await connection.getDealsByTimeRange(dateLimit, new Date());

        for (const analyse of parUser[userId]) {
          const symbAnalyse = (analyse.instrument || 'XAUUSD').toUpperCase();
          const dealsCorrespondants = (deals || []).filter(d => {
            if (!d.symbol || typeof d.profit !== 'number') return false;
            const sym = d.symbol.toUpperCase();
            const symMatch = sym.includes(symbAnalyse) || symbAnalyse.includes(sym.replace(/-.*/, ''));
            const dateMatch = new Date(d.time) > new Date(analyse.createdAt);
            const dirMatch = (analyse.decision === 'BUY' && d.type === 'DEAL_TYPE_SELL')
                          || (analyse.decision === 'SELL' && d.type === 'DEAL_TYPE_BUY');
            return symMatch && dateMatch && dirMatch;
          });
          if (!dealsCorrespondants.length) continue;
          dealsCorrespondants.sort((a, b) => new Date(a.time) - new Date(b.time));
          const deal = dealsCorrespondants[0];
          const profit = parseFloat(deal.profit);

          // Mettre à jour l'analyse avec le résultat
          await analysesDb.updateAsync(
            { _id: analyse._id },
            { $set: { tradeProfit: profit, tradeClotureTemps: deal.time, apprentissageStatut: 'TRAITE' }}
          );

          // Déclencher l'apprentissage selon le résultat
          const analyseAvecResultat = { ...analyse, tradeProfit: profit, tradeClotureTemps: deal.time };
          if (profit < 0) {
            // Perte → post-mortem auto
            await genererPostMortemAuto(analyseAvecResultat, userId);
          } else if (profit > 0) {
            // Gain → enregistrer comme setup gagnant
            await enregistrerSetupGagnant(analyseAvecResultat);
          }
        }
      } catch(err) {
        if (!err.message.includes('not found')) console.log('[APPRENTISSAGE] Erreur user:', err.message);
      }
    }
  } catch(err) { console.log('[APPRENTISSAGE] Erreur globale:', err.message); }
}
setInterval(surveillerTradesEtApprendre, 5 * 60 * 1000);

// ═══════════════════════════════════════════════════════════════════
// 🛡️ RATE LIMITER (protège la facture Anthropic)
// ═══════════════════════════════════════════════════════════════════
// Limite : 30 analyses/heure par utilisateur. Si dépassé → 429.
// Stockage en mémoire (reset au restart, pas grave).
const rateLimitStore = {};
function rateLimitAnalyze(req, res, next) {
  const userId = req.session?.userId;
  if (!userId) return next();

  // Admin = pas de limite
  if (req.session.userRole === 'admin') return next();

  const now = Date.now();
  const fenetre = 60 * 60 * 1000; // 1 heure
  const limite = 30; // 30 analyses/heure max

  if (!rateLimitStore[userId]) rateLimitStore[userId] = [];
  // Nettoyer les anciens timestamps
  rateLimitStore[userId] = rateLimitStore[userId].filter(t => now - t < fenetre);

  if (rateLimitStore[userId].length >= limite) {
    const tempsAttente = Math.ceil((fenetre - (now - rateLimitStore[userId][0])) / 60000);
    return res.status(429).json({
      error: `Trop d'analyses. Limite: ${limite}/heure. Réessaie dans ${tempsAttente} min.`,
      retryAfterMin: tempsAttente
    });
  }

  rateLimitStore[userId].push(now);
  next();
}

// Cleanup auto du store toutes les heures (évite de garder des données indéfiniment)
setInterval(() => {
  const now = Date.now();
  const fenetre = 60 * 60 * 1000;
  for (const userId of Object.keys(rateLimitStore)) {
    rateLimitStore[userId] = rateLimitStore[userId].filter(t => now - t < fenetre);
    if (rateLimitStore[userId].length === 0) delete rateLimitStore[userId];
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════════════════════════════
// 🩺 HEALTHCHECK (pour Render)
// ═══════════════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    memoryMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024)
  });
});

// Route idle (signal du frontend que l'utilisateur est inactif — pour économiser les ressources)
app.post('/api/idle', (req, res) => {
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════
// 💾 BACKUP AUTO DES DBs (1×/jour, rotation 7 jours)
// ═══════════════════════════════════════════════════════════════════
const BACKUP_DIR = path.join(__dirname, 'backups');
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

async function backupDatabases() {
  try {
    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const dossierJour = path.join(BACKUP_DIR, today);
    if (fs.existsSync(dossierJour)) return; // déjà fait aujourd'hui

    fs.mkdirSync(dossierJour, { recursive: true });

    const dbs = ['users.db', 'analyses.db', 'lecons.db', 'setups-gagnants.db'];
    for (const dbFile of dbs) {
      const src = path.join(__dirname, dbFile);
      const dest = path.join(dossierJour, dbFile);
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, dest);
      }
    }
    console.log('[BACKUP] DBs sauvegardées dans ' + today);

    // Rotation : garder 7 jours max
    const dossiers = fs.readdirSync(BACKUP_DIR).filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort();
    if (dossiers.length > 7) {
      for (const vieux of dossiers.slice(0, dossiers.length - 7)) {
        const cheminVieux = path.join(BACKUP_DIR, vieux);
        fs.rmSync(cheminVieux, { recursive: true, force: true });
      }
      console.log('[BACKUP] ' + (dossiers.length - 7) + ' anciens backups supprimés');
    }
  } catch(err) {
    console.log('[BACKUP] Erreur:', err.message);
  }
}
// Lancer au démarrage (5s après) puis toutes les 24h
setTimeout(backupDatabases, 5000);
setInterval(backupDatabases, 24 * 60 * 60 * 1000);

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
    paidUntil: user.paidUntil || null,
    mt5: user.mt5 ? {
      connected: true,
      login: user.mt5.login,
      server: user.mt5.server,
      accountType: user.mt5.accountType,
      capital: user.mt5.capital,
      currency: user.mt5.currency
    } : { connected: false }
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
      { $set: { feedbackResult: result, feedbackTime: new Date() } },
      {}
    );

    // Si SL touché → déclencher le post-mortem auto IMMÉDIATEMENT et attendre
    // la leçon pour la renvoyer au client
    if (result === 'sl') {
      const analyse = await analysesDb.findOneAsync({ _id: req.params.id, userId: req.session.userId });
      if (analyse && !analyse.leconId) {
        const perteEstimee = analyse.tradeProfit || -1;
        const analyseAvecPerte = {
          ...analyse,
          tradeProfit: perteEstimee,
          tradeClotureTemps: new Date()
        };
        try {
          const lecon = await genererPostMortemAuto(analyseAvecPerte, req.session.userId);
          if (lecon) {
            console.log('[FEEDBACK-SL] Leçon auto générée pour ' + req.params.id);
            return res.json({ success: true, lecon });
          }
        } catch(err) {
          console.log('[FEEDBACK-SL] Erreur:', err.message);
        }
      }
    }
    // Si TP touché → enregistrer comme setup gagnant
    else if (result === 'tp') {
      const analyse = await analysesDb.findOneAsync({ _id: req.params.id, userId: req.session.userId });
      if (analyse && !analyse.setupGagnantEnregistre) {
        const analyseGagnante = {
          ...analyse,
          tradeProfit: analyse.tradeProfit && analyse.tradeProfit > 0 ? analyse.tradeProfit : 1,
          tradeClotureTemps: new Date()
        };
        try {
          await enregistrerSetupGagnant(analyseGagnante);
          return res.json({ success: true, setupEnregistre: true });
        } catch(err) {
          console.log('[FEEDBACK-TP] Erreur:', err.message);
        }
      }
    }

    res.json({ success: true });
  } catch(e) { res.json({ error: e.message }); }
});

// ─── ROUTES APPRENTISSAGE IA ────────────────────────────────────────
// ─── ROUTES POST-MORTEM MANUEL (avec screen du SL touché) ─────
// Liste les trades perdants en attente d'analyse
app.get('/postmortem/pending', checkAuth, async (req, res) => {
  try {
    const enAttente = await analysesDb.findAsync({
      userId: req.session.userId,
      decision: { $in: ['BUY', 'SELL'] },
      tradeProfit: { $lt: 0 },
      postMortemScreen: { $exists: false }
    });
    enAttente.sort((a, b) => new Date(b.tradeClotureTemps || b.createdAt) - new Date(a.tradeClotureTemps || a.createdAt));
    res.json({ count: enAttente.length, analyses: enAttente.slice(0, 10) });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Upload du screen du SL pour analyse approfondie
app.post('/postmortem/:analysisId', checkAuth, upload.single('screen'), async (req, res) => {
  try {
    const analyse = await analysesDb.findOneAsync({
      _id: req.params.analysisId,
      userId: req.session.userId
    });
    if (!analyse) return res.status(404).json({ error: 'Analyse introuvable' });
    if (!req.file) return res.status(400).json({ error: 'Screen manquant' });

    const imageData = fs.readFileSync(req.file.path);
    const base64Image = imageData.toString('base64');
    const mimeType = req.file.mimetype || 'image/png';

    const promptText = `Tu es un trader expert ICT. Analyse ce trade qui a touché le SL en regardant le screen.

CONTEXTE :
- Instrument : ${analyse.instrument || 'XAUUSD'}
- Direction : ${analyse.decision}
- Entrée : ${analyse.entry}
- SL : ${analyse.sl}
- TP1 : ${analyse.tp}
- Score initial : ${analyse.score}/10
- Range asiatique : ${analyse.rangeBas || '?'} - ${analyse.rangeHaut || '?'}
- Perte : ${analyse.tradeProfit}$

L'utilisateur t'envoie le screen du moment où le SL a été touché.

MISSION :
1. Regarde le screen et identifie CE QUI A FOIRÉ visuellement
2. Identifie LE SIGNAL qu'il fallait voir avant pour éviter ce trade
3. Formule une LEÇON courte et actionnable

Réponds UNIQUEMENT en JSON :
{
  "ce_qui_a_foire": "explication courte (1 phrase)",
  "signal_manque": "le signal à voir avant (1 phrase concrète)",
  "lecon": "règle impérative pour les futures analyses (1 phrase)",
  "setup_type": "type de setup (CRT Kasper / OB+FVG / Range asiatique / etc.)"
}`;

    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 600,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: mimeType, data: base64Image }},
          { type: 'text', text: promptText }
        ]
      }]
    });

    try { fs.unlinkSync(req.file.path); } catch(e) {}

    const raw = response.content[0].text.trim();
    const m = raw.match(/\{[\s\S]*\}/);
    if (!m) return res.status(500).json({ error: 'Réponse non parseable', raw });
    const leconParsed = JSON.parse(m[0]);

    const leconId = uuidv4();
    await leconsDb.insertAsync({
      _id: leconId,
      userId: req.session.userId,
      analyseId: analyse._id,
      instrument: analyse.instrument,
      direction: analyse.decision,
      perte: analyse.tradeProfit,
      ceQuiAFoire: leconParsed.ce_qui_a_foire,
      signalManque: leconParsed.signal_manque,
      lecon: leconParsed.lecon,
      setupType: leconParsed.setup_type,
      auto: false,
      createdAt: new Date()
    });
    await analysesDb.updateAsync(
      { _id: analyse._id },
      { $set: { postMortemScreen: true, leconId }}
    );
    res.json({ success: true, lecon: leconParsed });
  } catch(err) {
    if (req.file) try { fs.unlinkSync(req.file.path); } catch(e) {}
    console.log('[POSTMORTEM] Erreur:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── NOTIFICATIONS ──────────────────────────────────────────────
app.get('/notifications', checkAuth, async (req, res) => {
  try {
    const notifs = await notificationsDb.findAsync({ userId: req.session.userId });
    notifs.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({
      count: notifs.length,
      nonLues: notifs.filter(n => !n.lue).length,
      notifications: notifs.slice(0, 30)
    });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/notifications/:id/lue', checkAuth, async (req, res) => {
  try {
    await notificationsDb.updateAsync(
      { _id: req.params.id, userId: req.session.userId },
      { $set: { lue: true } }
    );
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/notifications/lues', checkAuth, async (req, res) => {
  try {
    await notificationsDb.updateAsync(
      { userId: req.session.userId, lue: false },
      { $set: { lue: true } },
      { multi: true }
    );
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get('/apprentissage/lecons', checkAuth, async (req, res) => {
  try {
    const lecons = await leconsDb.findAsync({ userId: req.session.userId });
    lecons.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ count: lecons.length, lecons });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/apprentissage/lecons/:id', checkAuth, async (req, res) => {
  try {
    await leconsDb.removeAsync({ _id: req.params.id, userId: req.session.userId });
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get('/apprentissage/setups-gagnants', checkAuth, async (req, res) => {
  try {
    const setups = await setupsGagnantsDb.findAsync({ userId: req.session.userId });
    setups.sort((a, b) => b.profit - a.profit);
    res.json({ count: setups.length, setups: setups.slice(0, 20) });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/apprentissage/setups-gagnants/:id', checkAuth, async (req, res) => {
  try {
    await setupsGagnantsDb.removeAsync({ _id: req.params.id, userId: req.session.userId });
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/analyze', checkAuth, rateLimitAnalyze, uploadMulti.fields([
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

    // ─── CONTEXTE TEMPOREL (heure Paris + session) ───────────────────
    const nowParis = new Date().toLocaleString('fr-FR', { timeZone: 'Europe/Paris', hour: '2-digit', minute: '2-digit', hour12: false });
    const hourParis = parseInt(new Date().toLocaleString('fr-FR', { timeZone: 'Europe/Paris', hour: '2-digit', hour12: false }));
    let sessionActive, sessionWarning;
    if (hourParis >= 20 || hourParis < 8) {
      sessionActive = 'SESSION ASIATIQUE (range, faible volume)';
      sessionWarning = `⚠️ HEURE ACTUELLE: ${nowParis} (heure Paris) — SESSION ASIATIQUE EN COURS (20h00-08h00).
RÈGLE ABSOLUE SESSION ASIATIQUE :
- Le marché est en RANGE, faible directionnalité, faible volume
- Les faux breakouts sont TRÈS fréquents pendant cette session
- NE PAS TRADER sauf si : (1) cassure NETTE du range asiatique avec forte bougie + (2) score >= 8 + (3) confluence CRT + ICT claire
- Si le signal est dans le range asiatique sans cassure confirmée → NE PAS TRADER obligatoire (score automatique < 5)
- Le RSI en zone neutre (40-60) pendant la session asiatique = PAS de momentum suffisant → NE PAS TRADER
- Sois BEAUCOUP plus strict qu'en session Londres ou New York`;
    } else if (hourParis >= 8 && hourParis < 11) {
      sessionActive = 'OUVERTURE LONDRES (haute volatilité)';
      sessionWarning = `✅ HEURE ACTUELLE: ${nowParis} (heure Paris) — OUVERTURE SESSION LONDRES (08h00-11h00).
Session de haute volatilité, les setups ICT/CRT sont fiables. Analyse normale.`;
    } else if (hourParis >= 11 && hourParis < 13) {
      sessionActive = 'MI-JOURNÉE LONDRES (volatilité réduite)';
      sessionWarning = `⚠️ HEURE ACTUELLE: ${nowParis} (heure Paris) — MI-JOURNÉE LONDRES (11h00-13h00).
Volatilité en baisse, période de consolidation avant New York. Être plus sélectif, score minimum 7.`;
    } else if (hourParis >= 13 && hourParis < 17) {
      sessionActive = 'SESSION NEW YORK (haute volatilité)';
      sessionWarning = `✅ HEURE ACTUELLE: ${nowParis} (heure Paris) — SESSION NEW YORK (13h00-17h00).
Chevauchement Londres/New York, meilleure liquidité. Setups ICT/CRT très fiables. Analyse normale.`;
    } else {
      sessionActive = 'FIN SESSION NEW YORK (volume décroissant)';
      sessionWarning = `⚠️ HEURE ACTUELLE: ${nowParis} (heure Paris) — FIN SESSION NEW YORK / PRÉ-ASIATIQUE (17h00-20h00).
Volume décroissant, éviter les entrées tardives. Score minimum 7 requis.`;
    }

    // 📚 Leçons des trades perdants précédents
    const blocLecons = await getLeconsPourPrompt(req.session.userId);

    // 🏆 Setups gagnants précédents (patterns à reproduire)
    const blocSetupsGagnants = await getBlocSetupsGagnants(req.session.userId, req.body.instrument || 'XAUUSD');

    // 🔍 OB/FVG détectés algorithmiquement (data objective)
    const blocOBFVG = await getBlocOBFVG(req.session.userId, req.body.instrument || 'XAUUSD');

    // 📊 Indicateurs techniques (RSI + MAs sur H1/M15/M5)
    const blocIndicateurs = await getBlocIndicateursTechniques(req.session.userId, req.body.instrument || 'XAUUSD');

    content.push({
      type: 'text',
      text: `Tu es un trader ICT/Smart Money expérimenté qui aide un trader sur ${req.body.instrument || 'XAUUSD'}.${capital ? ` Capital: $${capital}.` : ''}

${blocLecons}${blocSetupsGagnants}${blocOBFVG}${blocIndicateurs}

CONTEXTE : ${sessionWarning}
SESSION : ${sessionActive}

═══════════════════════════════════════════════════════════════
🎯 TA MISSION
═══════════════════════════════════════════════════════════════
Analyse les ${nbTF} graphique(s) fournis (${tfDisponibles}) et donne UN signal de qualité OU dis "NE PAS TRADER".

Tu reçois aussi des données objectives calculées sur les vraies bougies MetaAPI :
- Indicateurs RSI/MA (ci-dessus dans 📊 INDICATEURS TECHNIQUES)
- OB/FVG algorithmiques (ci-dessus dans 🔍 NIVEAUX TECHNIQUES)
- Tes leçons passées et setups gagnants

⚠️ UTILISE CES DONNÉES, ne fais pas semblant. Si le bloc INDICATEURS te montre RSI ${'<'} 25 → c'est de la survente extrême, ne propose PAS de SELL. Si RSI > 75 → ne propose PAS de BUY. Si le prix est très loin sous MA50 → mouvement épuisé, prudence.

═══════════════════════════════════════════════════════════════
📊 RÈGLES SIMPLES
═══════════════════════════════════════════════════════════════

1. STRUCTURE D'ABORD
   - Tendance H1 et M30 alignées → setup possible dans ce sens
   - Tendance H1 ou M30 contre ton signal → score plafonné à 5 → NE PAS TRADER
   - Pas de structure claire → NE PAS TRADER

2. ENTRÉE LOGIQUE
   - Sur un OB, FVG, retest de breakout, ou range asiatique respecté
   - LIMIT si zone précise, MARKET si setup en cours et timing parfait
   - Si tu n'as PAS de niveau technique évident → NE PAS TRADER (ne force pas)

3. SL ET TP RÉALISTES
   - SL : derrière une zone de protection (OB/swing/liquidité), buffer 5-10$ sur XAU
   - TP1 : R:R 1:1.5 minimum, 1:2 idéal — PAS 1:3+ forcé
   - TP2 : R:R 1:2.5 ou 1:3 si niveau technique
   - Vise des niveaux atteignables, pas des chiffres ronds magiques

4. SCORING HONNÊTE
   - 9-10 : Setup A+ avec confluence multiple (CRT+OB+FVG+structure alignée+RSI sain)
   - 7-8 : Bon setup propre, structure claire, R:R correct
   - 5-6 : Signal présent mais incertain → NE PAS TRADER
   - 0-4 : Pas de setup → NE PAS TRADER

⛔ RÈGLES ABSOLUES :
- Si RSI extrême (< 25 ou > 75) contre ton signal → NE PAS TRADER
- Si bougie M15/M30 actuelle violente (3x+ la moyenne) → NE PAS TRADER (mouvement épuisé)
- Si tendance H1 ET M30 contre → NE PAS TRADER, peu importe le reste
- Si tu as une leçon précédente qui dit "ne pas faire X" → respecte-la

═══════════════════════════════════════════════════════════════
${crtKasperActif ? `🎯 CRT KASPER KARL (M15 + M1 fournis) — méthode principale
═══════════════════════════════════════════════════════════════
Cherche un pattern CRT sur les 3 DERNIÈRES bougies M15 UNIQUEMENT.
JAMAIS sur M1 ou M5 (pas de "mini CRT").

LES 3 BOUGIES :
• Bougie 1 (KEY CANDLE) : bougie de référence avec HIGH et LOW clairs
• Bougie 2 (SWEEP) :
  - Sa MÈCHE dépasse un extrême de la bougie 1 (chasse de liquidité)
  - Son CORPS ferme DANS le range de la bougie 1 (fausse cassure)
• Bougie 3 (BREAK) :
  - Ferme au-delà de l'extrême OPPOSÉ de la bougie 1
  - Doit avoir un corps significatif (pas une doji)

CRT BULLISH = sweep du LOW + close au-dessus du HIGH = BUY
CRT BEARISH = sweep du HIGH + close en-dessous du LOW = SELL

VARIANTES :
- STRICT : break net et clair → +2 score
- SOFT : effleure mais ferme de l'autre côté → +1 score
- Aucun pattern clair → crtKasper = "NON_DETECTE"

PLACEMENT (si CRT détecté) :
- Entrée : retest du niveau cassé (high/low de la key candle)
  Utilise M1 pour le timing précis
- SL : juste au-delà du sweep de la bougie 2 + buffer 5-10$ min
  → BUY : SL = low de bougie 2 - buffer
  → SELL : SL = high de bougie 2 + buffer
- TP1 : niveau de liquidité opposé, R:R 1:1.5 minimum

INTÉGRATION :
- CRT confirmé + tendance H1/M30 alignée → SETUP A+ (score 9-10)
- CRT confirmé + structure neutre → bon setup (score 7-8)
- CRT confirmé CONTRE H1/M30 → IGNORE le CRT, NE PAS TRADER
  (CRT contre tendance majeure = piège 80% du temps)
═══════════════════════════════════════════════════════════════
` : ''}

Réponds UNIQUEMENT avec un JSON valide, sans texte avant ou après, sans backticks:

{
  "decision": "BUY" ou "SELL" ou "NE PAS TRADER",
  "session": "${sessionActive}",
  "sessionImpact": "<comment la session influence ce signal>",
  "confiance": "XX%",
  "score": <0 à 10>,
  "tendance": "<M30>",
  "tendanceH1": "<H1 ou 'Non fourni'>",
  "tendanceM15": "<M15 ou 'Non fourni'>",
  "tendanceM5": "<M5 ou 'Non fourni'>",
  "tendanceM1": "<M1 ou 'Non fourni'>",
  "confluence": "<alignement TF>",
  "entree": "<prix d'entrée précis>",
  "entreeType": "LIMIT" ou "MARKET",
  "entreeLevel": "<description du niveau ex 'Retest OB H1 à 4675'>",
  "entreeStatut": "IMMEDIATE" ou "EN_ATTENTE",
  "sl": "<stop loss — min 50 pips XAU sauf CRT Kasper qui peut descendre à 30 pips>",
  "slPips": <nombre>,
  "tp1": "<TP1 — vise R:R 1:1.5 à 1:2>",
  "tp1Pips": <nombre>,
  "tp2": "<TP2 — vise R:R 1:2.5 à 1:3>",
  "tp2Pips": <nombre>,
  "tp3": "<TP3 optionnel — sur niveau majeur seulement>",
  "tp3Pips": <nombre>,
  "crt": "OUI" ou "NON" ou "NEUTRE",
  "crtDetail": "<explication>",
  ${crtKasperActif ? `"crtKasper": "DETECTE_BULLISH" ou "DETECTE_BEARISH" ou "NON_DETECTE",
  "crtKasperDetail": "<si détecté>",
  "crtKasperImpact": "<impact placement>",` : ''}
  "rangeHaut": "<HIGH range asiatique ou 'Non détecté'>",
  "rangeBas": "<LOW range asiatique ou 'Non détecté'>",
  "manipulation": "OUI" ou "NON",
  "manipulationDetail": "<détail ou 'Aucune'>",
  "ob": "<OB ou 'Aucun'>",
  "fvg": "<FVG ou 'Aucun'>",
  "obFvgConfluence": "<OUI/NON + niveau>",
  "liquidite": "<zones liquidité>",
  "confluences": "<confluences SMC>",
  "invalidation": "<invalidation>",
  "rsiUtilise": "<reprends ici les valeurs RSI que tu as vues dans le bloc INDICATEURS et explique COMMENT tu les as utilisées dans ta décision>",
  "instrument": "${req.body.instrument || 'XAUUSD'}",
  "risquePct": ${capital ? '<1 si score<6, 2 si score 6-7, 3 si score>=8>' : 'null'},
  "montantRisque": ${capital ? `<${capital} × risquePct / 100>` : 'null'},
  "capital": ${capital || 0}
}

⚠️ Le champ "rsiUtilise" est OBLIGATOIRE — il prouve que tu as bien lu les indicateurs.`
    });

    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 2500,
      system: 'Tu es un assistant trading expert. Tu reponds UNIQUEMENT avec du JSON valide, sans aucun texte avant ou apres, sans backticks, sans markdown. Juste le JSON brut commencant par { et finissant par }.',
      messages: [{ role: 'user', content }]
    });

    allFiles.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });

    let parsed;
    try {
      const rawText = response.content[0].text.trim();
      console.log('[IA RAW]', rawText.substring(0, 400));

      // Strategie 1 : parse direct si la reponse est deja du JSON propre
      try {
        parsed = JSON.parse(rawText);
      } catch(_) {
        // Strategie 2 : nettoyage puis extraction entre { et }
        let clean = rawText
          .replace(/```json\s*/gi, '')
          .replace(/```\s*/g, '')
          .replace(/^\s*[^{]*/s, '') // supprimer tout avant le premier {
          .trim();

        const first = clean.indexOf('{');
        const last  = clean.lastIndexOf('}');

        if (first === -1 || last === -1) {
          // Strategie 3 : chercher dans le texte original sans nettoyage
          const fRaw = rawText.indexOf('{');
          const lRaw = rawText.lastIndexOf('}');
          if (fRaw === -1 || lRaw === -1) {
            console.error('[PARSING] Reponse IA sans JSON:', rawText.substring(0, 300));
            throw new Error('Pas de JSON dans la reponse IA');
          }
          clean = rawText.substring(fRaw, lRaw + 1);
        } else {
          clean = clean.substring(first, last + 1);
        }

        try {
          parsed = JSON.parse(clean);
        } catch(e1) {
          // Strategie 4 : reparation des erreurs courantes
          const fixed = clean
            .replace(/,\s*}/g, '}')           // trailing comma
            .replace(/,\s*]/g, ']')
            .replace(/:\s*undefined/g, ':null') // undefined → null
            .replace(/([{,]\s*)(\w+)\s*:/g, '$1"$2":'); // cles sans guillemets
          parsed = JSON.parse(fixed);
        }
      }
    } catch(e) {
      console.error('[PARSING ERREUR]', e.message);
      console.error('[PARSING RAW]', response.content?.[0]?.text?.substring(0, 500));
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

    // ─── GARDE SCORE MINIMUM CÔTÉ SERVEUR ──────────────────────
    // Même si l'IA rate la règle, on force le refus si score < 6
    if (parsed.decision !== 'NE PAS TRADER' && (parsed.score || 0) < 6) {
      console.log('[SCORE-GUARD] Score ' + parsed.score + ' < 6 → NE PAS TRADER forcé côté serveur');
      parsed.decision = 'NE PAS TRADER';
      parsed.scoreGuardAlerte = 'Score trop faible (' + parsed.score + '/10) — minimum requis : 6/10 pour trader';
    }

    // ─── ANTI-PIÈGE RANGE ASIATIQUE (vérification post-IA) ────
    parsed = verifierPiegeRangeAsiatique(parsed);

    // ─── RÉAJUSTEMENT AUTO DE L'ENTRÉE (vs prix actuel MetaAPI) ───
    parsed = await reajusterEntreeSiNecessaire(parsed, req.session.userId);

    // ─── PROTECTIONS AVANCÉES (RSI extrême + mouvement épuisé + R:R réel) ───
    parsed = await verifierProtectionsAvancees(parsed, req.session.userId);

    // ─── CALCUL LOTS CÔTÉ SERVEUR (garanti) ──────────────────
    if (capital && parsed.slPips && parsed.decision !== 'NE PAS TRADER') {
      const score = parsed.score || 0;
      const risquePct = score >= 8 ? 3 : score >= 6 ? 2 : 1;
      parsed.risquePct = risquePct;
      parsed.lots = calculerLots(capital, risquePct, parsed.slPips, parsed.instrument || '');
      parsed.montantRisque = (capital * risquePct / 100).toFixed(2);

      // ─── LOT DYNAMIQUE (anti-drawdown / anti-tilt) ──────────
      const { facteur, alerte } = await getFacteurRisque(req.session.userId, capital);
      if (facteur < 1 && parsed.lots) {
        const lotsOriginaux = parseFloat(parsed.lots);
        parsed.lots = Math.max(0.01, Math.round(lotsOriginaux * facteur * 100) / 100).toFixed(2);
        parsed.montantRisque = (parseFloat(parsed.montantRisque) * facteur).toFixed(2);
        parsed.lotDynamiqueAlerte = alerte;
        console.log('[LOT-DYNAMIQUE] User ' + req.session.userId + ' : ' + lotsOriginaux + ' → ' + parsed.lots + ' (' + alerte + ')');
      }
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

// ─── ROUTES ADMIN AVANCÉES ──────────────────────────────────────────

// Statistiques de feedback (TP/SL/En cours + Win Rate IA)
app.get('/admin/feedback', checkAdmin, async (req, res) => {
  try {
    const all = await analysesDb.findAsync({});
    const tp = all.filter(a => a.feedbackResult === 'tp').length;
    const sl = all.filter(a => a.feedbackResult === 'sl').length;
    const pending = all.filter(a => a.feedbackResult === 'pending').length;
    const total = tp + sl;
    const winrate = total > 0 ? Math.round((tp / total) * 100) : 0;
    res.json({ tp, sl, pending, winrate, totalAnalyses: all.length });
  } catch(e) { res.json({ error: e.message }); }
});

// Dashboard avancé : MRR, croissance, churn, win rate global, top users
app.get('/admin/dashboard', checkAdmin, async (req, res) => {
  try {
    const users = await db.findAsync({ role: { $ne: 'admin' } });
    const analyses = await analysesDb.findAsync({});
    const now = new Date();
    const debutMois = new Date(now.getFullYear(), now.getMonth(), 1);
    const debutMoisDernier = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const finMoisDernier = new Date(now.getFullYear(), now.getMonth(), 0, 23, 59, 59);
    const il_y_a_7j = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const il_y_a_30j = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    // MRR (clients abonnés × prix moyen — adapter selon tarif)
    const payants = users.filter(u => u.subscribed && u.paymentStatus === 'paid');
    const prixMoyen = parseFloat(process.env.PRIX_ABONNEMENT) || 50;
    const mrr = payants.length * prixMoyen;

    // Croissance mensuelle
    const inscritsCeMois = users.filter(u => u.createdAt && new Date(u.createdAt) >= debutMois).length;
    const inscritsMoisDernier = users.filter(u => u.createdAt && new Date(u.createdAt) >= debutMoisDernier && new Date(u.createdAt) <= finMoisDernier).length;
    const croissancePct = inscritsMoisDernier > 0
      ? Math.round(((inscritsCeMois - inscritsMoisDernier) / inscritsMoisDernier) * 100)
      : 0;

    // Activité
    const actifs7j = users.filter(u => u.lastLogin && new Date(u.lastLogin) >= il_y_a_7j).length;
    const actifs30j = users.filter(u => u.lastLogin && new Date(u.lastLogin) >= il_y_a_30j).length;

    // Win rate global plateforme (basé sur feedback)
    const tradesAvecFb = analyses.filter(a => a.feedbackResult === 'tp' || a.feedbackResult === 'sl');
    const tradesGagnants = analyses.filter(a => a.feedbackResult === 'tp');
    const winRateGlobal = tradesAvecFb.length > 0
      ? Math.round((tradesGagnants.length / tradesAvecFb.length) * 100)
      : 0;

    // Apprentissage IA — totaux globaux
    const totalLecons = await leconsDb.countAsync({});
    const totalSetupsGagnants = await setupsGagnantsDb.countAsync({});

    // Top 5 users par activité
    const statsParUser = users.map(u => {
      const userAnalyses = analyses.filter(a => a.userId === u._id);
      return {
        id: u._id,
        email: u.email,
        analyses: userAnalyses.length,
        analysesCeMois: userAnalyses.filter(a => new Date(a.createdAt) >= debutMois).length,
        derniereActivite: u.lastLogin || u.createdAt,
        plan: u.plan || 'aucun',
        subscribed: !!u.subscribed
      };
    });
    const topUsers = [...statsParUser].sort((a, b) => b.analyses - a.analyses).slice(0, 5);

    // Analyses 7j / 30j
    const analyses7j = analyses.filter(a => new Date(a.createdAt) >= il_y_a_7j).length;
    const analyses30j = analyses.filter(a => new Date(a.createdAt) >= il_y_a_30j).length;

    res.json({
      mrr,
      clientsPayants: payants.length,
      prixMoyen,
      inscritsCeMois,
      inscritsMoisDernier,
      croissancePct,
      actifs7j,
      actifs30j,
      winRateGlobal,
      tradesAvecFb: tradesAvecFb.length,
      analyses7j,
      analyses30j,
      apprentissage: {
        totalLecons,
        totalSetupsGagnants
      },
      topUsers
    });
  } catch(e) {
    console.log('[ADMIN-DASHBOARD]', e.message);
    res.json({ error: e.message });
  }
});

// Liste des leçons globales (toutes confondues, vue admin)
app.get('/admin/lecons', checkAdmin, async (req, res) => {
  try {
    const lecons = await leconsDb.findAsync({});
    lecons.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    // Joindre l'email du user
    const users = await db.findAsync({});
    const usersMap = {};
    users.forEach(u => { usersMap[u._id] = u.email; });
    res.json({
      count: lecons.length,
      lecons: lecons.slice(0, 30).map(l => ({
        ...l,
        userEmail: usersMap[l.userId] || 'inconnu'
      }))
    });
  } catch(e) { res.json({ error: e.message }); }
});

// Liste des setups gagnants globaux
app.get('/admin/setups-gagnants', checkAdmin, async (req, res) => {
  try {
    const setups = await setupsGagnantsDb.findAsync({});
    setups.sort((a, b) => b.profit - a.profit);
    const users = await db.findAsync({});
    const usersMap = {};
    users.forEach(u => { usersMap[u._id] = u.email; });
    res.json({
      count: setups.length,
      setups: setups.slice(0, 30).map(s => ({
        ...s,
        userEmail: usersMap[s.userId] || 'inconnu'
      }))
    });
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

// ═══════════════════════════════════════════════════════════════════
// 🔌 ROUTES METAAPI — CONNEXION MT5 DU CLIENT
// ═══════════════════════════════════════════════════════════════════

// Helper : chercher un compte MetaApi existant par login (evite les doublons)
// Utilise la pagination moderne avec fallback sur l'ancienne API
async function findMetaApiAccountByLogin(login) {
  if (!metaApi) throw new Error('MetaApi non configure');
  const accountsApi = metaApi.metatraderAccountApi;
  const loginStr = String(login);

  // Methode moderne : getAccountsWithInfiniteScrollPagination (MetaApi v29+)
  if (typeof accountsApi.getAccountsWithInfiniteScrollPagination === 'function') {
    let page = 0;
    while (page < 50) { // max 5000 comptes
      try {
        const resp = await accountsApi.getAccountsWithInfiniteScrollPagination({
          limit: 100,
          offset: page * 100
        });
        const items = resp.items || resp || [];
        if (items.length === 0) break;
        const found = items.find(a => String(a.login) === loginStr);
        if (found) return found;
        if (items.length < 100) break;
        page++;
      } catch(e) {
        console.log('[METAAPI] Pagination erreur:', e.message);
        break;
      }
    }
    return null;
  }

  // Fallback : ancienne API getAccounts
  if (typeof accountsApi.getAccounts === 'function') {
    const accounts = await accountsApi.getAccounts({});
    return accounts.find(a => String(a.login) === loginStr);
  }

  // Fallback ultime : getAccountsWithClassicScrollPagination
  if (typeof accountsApi.getAccountsWithClassicScrollPagination === 'function') {
    const resp = await accountsApi.getAccountsWithClassicScrollPagination({ limit: 1000 });
    const items = resp.items || resp || [];
    return items.find(a => String(a.login) === loginStr);
  }

  throw new Error('Aucune methode getAccounts disponible dans MetaApi SDK');
}

// Helper : chiffrer + sauvegarder credentials MT5 d'un user
async function saveMT5Credentials(userId, mt5Data) {
  const encryptedPassword = encryptStr(mt5Data.password);
  await db.updateAsync(
    { _id: userId },
    { $set: {
      mt5: {
        login: String(mt5Data.login),
        passwordEnc: encryptedPassword,
        server: mt5Data.server,
        accountType: mt5Data.accountType || 'demo',
        metaApiAccountId: mt5Data.metaApiAccountId,
        capital: mt5Data.capital || null,
        currency: mt5Data.currency || 'USD',
        connectedAt: new Date().toISOString()
      }
    }}
  );
}

// ─── POST /mt5/connect : connecter le compte MT5 du client ──────────
// Réutilise les comptes MetaApi existants (créés par le bot ou par le site)
// Permet aussi de changer de compte (écrase l'ancienne connexion proprement)
app.post('/mt5/connect', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecte' });
  if (!metaApi) return res.status(500).json({ error: 'MetaApi non configure cote serveur' });

  const { login, password, accountType } = req.body;
  // Normalisation du nom de serveur : "VTMarkets-Live6" → "VTMarkets-Live 6"
  // MetaApi exige un espace avant le chiffre final (ex: "VTMarkets-Live 6")
  let server = (req.body.server || '').trim();
  server = server.replace(/([A-Za-z])(\d+)$/, '$1 $2');

  if (!login || !password || !server) {
    return res.status(400).json({ error: 'Login, password et serveur sont requis' });
  }

  let account;
  try {
    console.log('[MT5-CONNECT] User ' + req.session.userId + ' connecte MT5 ' + login + ' / ' + server);

    // ─── Étape 1 : Chercher un compte existant dans MetaApi ─────────
    // (ce login peut deja avoir un compte MetaApi cree par le bot Telegram
    // Flag pour savoir si le compte vient d'etre cree (besoin de plus de temps)
    let isNewAccount = false;

    //  ou par une connexion precedente du site → on REUTILISE, pas de doublon)
    account = await findMetaApiAccountByLogin(login);

    if (account) {
      console.log('[MT5-CONNECT] Compte existant trouve: ' + account.id + ' (reutilise)');
    } else {
      // ─── Étape 2 : Pas de compte trouve → en creer un nouveau ─────
      console.log('[MT5-CONNECT] Compte non trouve, creation...');
      isNewAccount = true;
      try {
        account = await metaApi.metatraderAccountApi.createAccount({
          name: 'AIM-' + login + '-' + (accountType || 'demo'),
          type: 'cloud',
          login: String(login),
          password: password,
          server: server,
          platform: 'mt5',
          magic: 12345,
          application: 'MetaApi'
        });
        console.log('[MT5-CONNECT] Compte cree: ' + account.id + ' — attente provisioning 10s...');
        // Laisser le temps a MetaApi de provisionner les ressources
        await new Promise(r => setTimeout(r, 10000));
      } catch(createErr) {
        console.log('[MT5-CONNECT] Erreur creation, retry recherche:', createErr.message);
        account = await findMetaApiAccountByLogin(login);
        if (!account) throw createErr;
        isNewAccount = false;
      }
    }

    // ─── Étape 3 : Polling actif de l'état du compte ──────────────
    // On veut un compte DEPLOYED + CONNECTED avant de tenter la sync
    // Si pas DEPLOYED → deploy + poll jusqu'a ce qu'il le soit
    // Si DEPLOYED mais DISCONNECTED → on attend la connexion broker

    // Helper : reload l'etat reel du compte depuis MetaApi
    const reloadAccount = async () => {
      try {
        await account.reload();
      } catch(e) {
        // reload() n'existe pas dans toutes les versions du SDK
        // → on utilise la methode alternative de getAccount
        try {
          const fresh = await metaApi.metatraderAccountApi.getAccount(account.id);
          account = fresh;
        } catch(e2) {}
      }
    };

    // Etape 3a : reload pour avoir l'etat reel
    await reloadAccount();
    console.log('[MT5-CONNECT] Etat reel: state=' + account.state + ' connection=' + account.connectionStatus);

    // Etape 3b : Si UNDEPLOYED, deploy
    if (account.state === 'UNDEPLOYED' || account.state === 'UNDEPLOYING') {
      console.log('[MT5-CONNECT] Deploy en cours...');
      try {
        await account.deploy();
        trackDeploy(account.id, login);
      } catch(deployErr) {
        if (!String(deployErr.message).includes('already')) {
          console.log('[MT5-CONNECT] Deploy warning:', deployErr.message);
        }
        trackDeploy(account.id, login);
      }
    } else if (account.state === 'DEPLOYED') {
      console.log('[MT5-CONNECT] Compte deja DEPLOYED, on track quand meme');
      trackDeploy(account.id, login);
    } else {
      console.log('[MT5-CONNECT] Etat ' + account.state + ', on attend stabilisation...');
      trackDeploy(account.id, login);
    }

    // Etape 3c : POLLING actif jusqu'a CONNECTED ou timeout
    // C'est PLUS FIABLE que waitConnected qui peut planter avec un timeout silencieux
    const maxPollTime = isNewAccount ? 180000 : 150000; // 3 min ou 2.5 min
    const pollStart = Date.now();
    let isStable = false;

    while (Date.now() - pollStart < maxPollTime) {
      await new Promise(r => setTimeout(r, 5000)); // attendre 5s entre chaque check
      await reloadAccount();
      const elapsed = Math.round((Date.now() - pollStart) / 1000);
      console.log('[MT5-CONNECT] Poll ' + elapsed + 's: state=' + account.state + ' connection=' + account.connectionStatus);

      if (account.state === 'DEPLOYED' && account.connectionStatus === 'CONNECTED') {
        console.log('[MT5-CONNECT] ✅ Compte stable et connecte au broker !');
        isStable = true;
        break;
      }
    }

    if (!isStable) {
      // ON NE FAIT PAS UNDEPLOY ! Le watchdog le fera dans 5 min si necessaire
      // L'utilisateur peut retenter dans 1 min, le compte aura peut-etre eu le temps
      console.log('[MT5-CONNECT] Timeout polling — compte en cours de connexion, le watchdog gerera');
      throw new Error(
        'Connexion en cours côté broker — réessaye dans 1 minute. ' +
        '(Si ça persiste, vérifie tes identifiants MT5 ou le serveur ' + server + '.)'
      );
    }

    // ─── Étape 4 : Récupérer la connexion + capital ────────────────
    let accountInfo;
    try {
      const connection = account.getRPCConnection();
      await connection.connect();
      console.log('[MT5-CONNECT] WaitSynchronized (timeout 60s)...');
      await connection.waitSynchronized({ timeoutInSeconds: 60 });
      accountInfo = await connection.getAccountInformation();
      console.log('[MT5-CONNECT] ✅ Capital récupéré: ' + accountInfo.balance + ' ' + accountInfo.currency);
    } catch(syncErr) {
      console.log('[MT5-CONNECT] Sync failed:', syncErr.message);
      // ON NE TOUCHE PAS AU UNDEPLOY — laisse le watchdog faire son job
      throw new Error('La connexion au broker a démarré mais la sync échoue. Réessaye dans 1 minute.');
    }

    // ─── Étape 6 : Sauvegarder les credentials chiffres ────────────
    await saveMT5Credentials(req.session.userId, {
      login,
      password,
      server,
      accountType: accountType || 'demo',
      metaApiAccountId: account.id,
      capital: accountInfo.balance,
      currency: accountInfo.currency
    });

    // ─── Étape 5 : NE PAS UNDEPLOY ────────────────────────────────
    // On laisse le compte deployed pour quelques minutes :
    // - L'utilisateur peut placer un ordre juste apres
    // - Le watchdog l'undeploy automatiquement apres 5 min d'inactivite
    // - Evite les race conditions deploy/undeploy trop rapides
    console.log('[MT5-CONNECT] ✅ Connexion reussie — compte reste deployed (watchdog auto-undeploy dans 5 min)');

    res.json({
      success: true,
      capital: accountInfo.balance,
      currency: accountInfo.currency,
      login: accountInfo.login,
      server: accountInfo.server,
      name: accountInfo.name,
      reused: !!account // true si on a reutilise un compte existant
    });
  } catch (err) {
    console.error('[MT5-CONNECT] Erreur:', err.message);

    // Detection precise du probleme pour message client clair
    let userMsg = err.message;
    if (err.message.includes('not connected to broker yet') || err.message.includes('Failed to subscribe')) {
      userMsg = 'Ton compte MT5 n\'arrive pas a se connecter au broker VTMarkets. ' +
                'Verifie que ton MT5 mobile/desktop est bien en ligne. ' +
                'Si le probleme persiste, ton compte demo a peut-etre expire — recree un nouveau demo et reessaie.';
    } else if (err.message.includes('Invalid') || err.message.includes('invalid')) {
      userMsg = 'Identifiants MT5 invalides. Verifie ton login, mot de passe et nom du serveur.';
    } else if (err.message.includes('connection') || err.message.includes('timeout')) {
      userMsg = 'Impossible de se connecter au broker (timeout). Reessaie dans 1-2 minutes ou verifie ton serveur MT5.';
    } else if (err.message.includes('region')) {
      userMsg = 'Probleme de region MetaApi. Contacte le support — c\'est un probleme cote serveur.';
    }

    res.status(500).json({
      error: 'Connexion echouee',
      details: userMsg,
      raw: err.message
    });
  }
});

// ─── POST /mt5/switch : changer de compte MT5 ────────────────────────
// Undeploy l'ancien compte MetaApi AVANT de switch pour éviter la facturation inutile
app.post('/mt5/switch', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecte' });
  try {
    // Récupérer l'ancien compte MetaApi et l'undeploy proprement
    const user = await db.findOneAsync({ _id: req.session.userId });
    if (user && user.mt5 && user.mt5.metaApiAccountId && metaApi) {
      try {
        const oldAccount = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
        if (oldAccount && oldAccount.state !== 'UNDEPLOYED') {
          await oldAccount.undeploy();
          trackUndeploy(oldAccount.id);
          console.log('[MT5-SWITCH] Ancien compte undeploye: ' + user.mt5.metaApiAccountId + ' (login ' + user.mt5.login + ')');
        }
      } catch(undeployErr) {
        // Ne pas bloquer le switch si l'undeploy echoue, le watchdog prendra le relais
        console.log('[MT5-SWITCH] Undeploy ancien compte echoue (watchdog prendra le relais):', undeployErr.message);
      }
    }

    // Supprimer les credentials de l'utilisateur en DB
    await db.updateAsync(
      { _id: req.session.userId },
      { $unset: { mt5: true } }
    );
    console.log('[MT5-SWITCH] User ' + req.session.userId + ' a switch de compte');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── POST /mt5/disconnect : deconnecter le compte MT5 ───────────────
app.post('/mt5/disconnect', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecte' });
  try {
    await db.updateAsync(
      { _id: req.session.userId },
      { $unset: { mt5: true } }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── GET /mt5/status : etat de la connexion MT5 du user ─────────────
app.get('/mt5/status', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecte' });
  const user = await db.findOneAsync({ _id: req.session.userId });
  if (!user || !user.mt5) return res.json({ connected: false });
  res.json({
    connected: true,
    login: user.mt5.login,
    server: user.mt5.server,
    accountType: user.mt5.accountType,
    capital: user.mt5.capital,
    currency: user.mt5.currency,
    connectedAt: user.mt5.connectedAt
  });
});

// ─── POST /mt5/refresh-capital : refresh capital depuis MT5 ─────────
// Deploy le compte temporairement pour recuperer le capital actuel
app.post('/mt5/refresh-capital', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecte' });
  if (!metaApi) return res.status(500).json({ error: 'MetaApi non configure' });

  const user = await db.findOneAsync({ _id: req.session.userId });
  if (!user || !user.mt5 || !user.mt5.metaApiAccountId) {
    return res.status(404).json({ error: 'MT5 non connecte' });
  }

  try {
    const account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
    await account.deploy();
    trackDeploy(account.id, user.mt5.login);
    await account.waitConnected();
    const connection = account.getRPCConnection();
    await connection.connect();
    await connection.waitSynchronized();
    const info = await connection.getAccountInformation();
    await account.undeploy();
    trackUndeploy(account.id);

    await db.updateAsync(
      { _id: req.session.userId },
      { $set: { 'mt5.capital': info.balance, 'mt5.currency': info.currency } }
    );

    res.json({ capital: info.balance, currency: info.currency });
  } catch (err) {
    console.error('[MT5-REFRESH] Erreur:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── POST /mt5/place-order : placer un ordre LIMIT (deploy on-demand) ─
app.post('/mt5/place-order', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecte' });
  if (!metaApi) return res.status(500).json({ error: 'MetaApi non configure' });

  const { symbol, direction, volume, entryPrice, sl, tp } = req.body;
  if (!symbol || !direction || !volume || !entryPrice || !sl) {
    return res.status(400).json({ error: 'Donnees ordre incompletes' });
  }

  const user = await db.findOneAsync({ _id: req.session.userId });
  if (!user || !user.mt5 || !user.mt5.metaApiAccountId) {
    return res.status(404).json({ error: 'MT5 non connecte. Connecte ton compte d\'abord.' });
  }

  let account;
  try {
    console.log('[MT5-ORDER] Place ' + direction + ' ' + symbol + ' ' + volume + ' lots @ ' + entryPrice);

    account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
    await account.deploy();
    trackDeploy(account.id, user.mt5.login);
    await account.waitConnected();

    const connection = account.getRPCConnection();
    await connection.connect();
    await connection.waitSynchronized();

    // ─── RESOLUTION DU SYMBOLE BROKER ────────────────────────────────
    // VTMarkets (et d'autres brokers) utilisent des suffixes sur les symboles
    // ex: XAUUSD → XAUUSD-VIP ou XAUUSD-STD selon le type de compte
    // On teste le symbole brut d'abord, puis les variantes courantes
    const resolveSymbol = async (baseSymbol) => {
      const suffixes = ['', '-VIP', '-STD', '-ECN', '-PRO', '-Raw', '.a', '_m', '-micro'];
      for (const suffix of suffixes) {
        const candidate = baseSymbol + suffix;
        try {
          const tick = await connection.getSymbolPrice(candidate);
          if (tick && tick.bid) {
            console.log('[MT5-ORDER] Symbole resolu: ' + candidate + ' (bid=' + tick.bid + ')');
            return { resolvedSymbol: candidate, currentPrice: tick.bid };
          }
        } catch(e) {
          // Ce suffixe n'existe pas sur ce broker, on essaie le suivant
        }
      }
      throw new Error('Symbole ' + baseSymbol + ' introuvable sur ce compte broker. Verifie le nom exact dans ton MT5.');
    };

    const { resolvedSymbol, currentPrice } = await resolveSymbol(symbol);
    const isBuy = String(direction).toUpperCase().includes('BUY');

    let orderType;
    if (isBuy) {
      orderType = parseFloat(entryPrice) < currentPrice ? 'ORDER_TYPE_BUY_LIMIT' : 'ORDER_TYPE_BUY_STOP';
    } else {
      orderType = parseFloat(entryPrice) > currentPrice ? 'ORDER_TYPE_SELL_LIMIT' : 'ORDER_TYPE_SELL_STOP';
    }

    console.log('[MT5-ORDER] Symbole final: ' + resolvedSymbol + ' | Type: ' + orderType + ' | Prix actuel: ' + currentPrice);

    // Placer l'ordre avec le symbole resolu
    const result = isBuy
      ? (orderType === 'ORDER_TYPE_BUY_LIMIT'
          ? await connection.createLimitBuyOrder(resolvedSymbol, parseFloat(volume), parseFloat(entryPrice), parseFloat(sl), tp ? parseFloat(tp) : null, { comment: 'AIM' })
          : await connection.createStopBuyOrder(resolvedSymbol, parseFloat(volume), parseFloat(entryPrice), parseFloat(sl), tp ? parseFloat(tp) : null, { comment: 'AIM' }))
      : (orderType === 'ORDER_TYPE_SELL_LIMIT'
          ? await connection.createLimitSellOrder(resolvedSymbol, parseFloat(volume), parseFloat(entryPrice), parseFloat(sl), tp ? parseFloat(tp) : null, { comment: 'AIM' })
          : await connection.createStopSellOrder(resolvedSymbol, parseFloat(volume), parseFloat(entryPrice), parseFloat(sl), tp ? parseFloat(tp) : null, { comment: 'AIM' }));

    console.log('[MT5-ORDER] Ordre place ! ID:', result.orderId);

    // UNDEPLOY immediatement pour economiser
    await account.undeploy();
    trackUndeploy(account.id);

    res.json({
      success: true,
      orderId: result.orderId,
      orderType,
      message: 'Ordre place sur ton MT5 ✓'
    });
  } catch (err) {
    console.error('[MT5-ORDER] Erreur:', err.message);
    // Tenter de undeploy meme en cas d'erreur
    if (account) {
      try {
        await account.undeploy();
        trackUndeploy(account.id);
      } catch(e) {}
    }
    res.status(500).json({ error: err.message });
  }
});

// ─── POST /analyses/:id/place-order : tracker l'usage du bouton ─────
app.post('/analyses/:id/place-order', async (req, res) => {
  try {
    await analysesDb.updateAsync(
      { _id: req.params.id },
      { $set: {
        orderPlaced: true,
        placeMethod: req.body.method || 'unknown',
        orderId: req.body.orderId || null,
        placedAt: new Date().toISOString()
      }}
    );
    res.json({ ok: true });
  } catch(e) {
    res.json({ ok: false });
  }
});

if (!fs.existsSync(path.join(__dirname, 'uploads'))) fs.mkdirSync(path.join(__dirname, 'uploads'));

// ═══════════════════════════════════════════════════════════════════
// 🛟 GESTION D'ERREUR GLOBALE
// ═══════════════════════════════════════════════════════════════════
// Catch les erreurs non gérées dans les routes Express
app.use((err, req, res, next) => {
  console.error('[ERREUR-EXPRESS]', err.message);
  console.error(err.stack);
  if (res.headersSent) return next(err);
  res.status(500).json({
    error: 'Erreur serveur',
    message: process.env.NODE_ENV === 'production' ? 'Quelque chose a foiré, réessaie' : err.message
  });
});

// Catch les erreurs async non catchées (qui crasheraient le process)
process.on('unhandledRejection', (reason, promise) => {
  console.error('[UNHANDLED-REJECTION]', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT-EXCEPTION]', err.message);
  console.error(err.stack);
  // Ne pas exit, laisser le serveur tourner
});

app.listen(port, () => {
  console.log('✅ Serveur lancé sur http://localhost:' + port);
  console.log('   Mode :', process.env.NODE_ENV || 'development');
  console.log('   PID  :', process.pid);
});