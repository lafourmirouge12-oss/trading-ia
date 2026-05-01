require('dotenv').config();
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const Datastore = require('@seald-io/nedb');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');

// FIX problème 11 : déduplication analyses simultanées par utilisateur
const _analysisLocks = new Map(); // userId → timestamp début analyse
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

let deployTracker = {}; // sera initialisé après loadTracker // { accountId: { deployedAt: ms, login: string } }
// ═══════════════════════════════════════════════════════════════════
// 🛡️ WATCHDOG ULTRA-RENFORCÉ — protection contre les comptes "fantômes"
// ═══════════════════════════════════════════════════════════════════
// Objectif : qu'AUCUN compte MetaApi ne reste deployed > 90s sans raison.
//
// Stratégie multi-couches :
//   1. Tracker en mémoire (rapide) + persisté sur disque (survit aux restarts)
//   2. Watchdog interne toutes les 30s → undeploy comptes du tracker > 90s
//   3. Boot scan au démarrage → undeploy tous les comptes orphelins
//   4. Hard scan toutes les 10 min → scanne TOUS les comptes MetaApi et
//      undeploy ceux qui sont deployed depuis trop longtemps (FILET DE SÉCURITÉ
//      ULTIME contre les comptes fantômes que le tracker a perdu)
//
// Persistance : on stocke le tracker dans deploy-tracker.json toutes les 10s.
// Si le serveur crash, au redémarrage on relit le fichier et on continue.

const MAX_DEPLOY_MS = 90 * 1000; // 90 secondes max (réduit de 2 min)
const WATCHDOG_INTERVAL = 30 * 1000; // check toutes les 30s
const HARD_SCAN_INTERVAL = 10 * 60 * 1000; // scan profond toutes les 10 min
const TRACKER_FILE = path.join(__dirname, 'deploy-tracker.json');

// Charger le tracker au démarrage
function loadTracker() {
  try {
    if (fs.existsSync(TRACKER_FILE)) {
      const data = JSON.parse(fs.readFileSync(TRACKER_FILE, 'utf-8'));
      console.log('[WATCHDOG] Tracker rechargé : ' + Object.keys(data).length + ' comptes en mémoire');
      return data || {};
    }
  } catch(e) { console.log('[WATCHDOG] Erreur lecture tracker:', e.message); }
  return {};
}

// Sauvegarder le tracker (appelé après chaque modif + toutes les 10s)
function saveTracker() {
  try {
    fs.writeFileSync(TRACKER_FILE, JSON.stringify(deployTracker, null, 2));
  } catch(e) { console.log('[WATCHDOG] Erreur écriture tracker:', e.message); }
}

// Marquer un compte comme deployé
function trackDeploy(accountId, login) {
  if (!accountId) return;
  deployTracker[accountId] = {
    deployedAt: Date.now(),
    login: login || 'unknown'
  };
  console.log('[WATCHDOG] Deploy tracked: ' + accountId + ' (' + login + ')');
  saveTracker();
}

// Marquer un compte comme undeployé (le retire du tracker)
function trackUndeploy(accountId) {
  if (deployTracker[accountId]) {
    const elapsed = Math.round((Date.now() - deployTracker[accountId].deployedAt) / 1000);
    console.log('[WATCHDOG] Undeploy tracked: ' + accountId + ' (apres ' + elapsed + 's)');
    delete deployTracker[accountId];
    saveTracker();
  }
}

// Watchdog interne : vérifie le tracker toutes les 30s
async function watchdogCheck() {
  if (!metaApi) return;
  const now = Date.now();
  const expired = Object.entries(deployTracker).filter(
    ([id, data]) => (now - data.deployedAt) > MAX_DEPLOY_MS
  );

  if (expired.length === 0) return;

  console.log('[WATCHDOG] ' + expired.length + ' compte(s) deployes > 90s → undeploy force');

  for (const [accountId, data] of expired) {
    try {
      const account = await metaApi.metatraderAccountApi.getAccount(accountId);
      if (account && account.state !== 'UNDEPLOYED') {
        await account.undeploy();
        console.log('[WATCHDOG] ✅ Undeploy force pour ' + accountId + ' (login ' + data.login + ', age ' + Math.round((now - data.deployedAt)/1000) + 's)');
      }
    } catch (err) {
      console.log('[WATCHDOG] Erreur undeploy ' + accountId + ':', err.message);
    } finally {
      delete deployTracker[accountId];
      saveTracker();
    }
  }
}

// HARD SCAN : filet de sécurité ultime contre les comptes "fantômes"
// Scanne TOUS les comptes MetaApi (pas seulement ceux du tracker) et
// undeploy ceux qui sont DEPLOYED. Toutes les 10 min.
async function hardScanComptesFantomes() {
  if (!metaApi) return;
  try {
    const accountsApi = metaApi.metatraderAccountApi;
    let allAccounts = [];

    if (typeof accountsApi.getAccountsWithInfiniteScrollPagination === 'function') {
      let page = 0;
      while (page < 50) {
        try {
          const resp = await accountsApi.getAccountsWithInfiniteScrollPagination({ limit: 100, offset: page * 100 });
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

    const aimDeployed = allAccounts.filter(a =>
      String(a.name || '').startsWith('AIM-') && a.state !== 'UNDEPLOYED'
    );

    if (aimDeployed.length > 0) {
      console.log('[HARD-SCAN] ⚠️ ' + aimDeployed.length + ' compte(s) AIM deployed détectés');

      for (const acc of aimDeployed) {
        // Si ce compte n'est PAS dans le tracker OU son temps tracker > 90s → undeploy
        const tracked = deployTracker[acc.id];
        const now = Date.now();
        const ageTracker = tracked ? (now - tracked.deployedAt) : Infinity;

        if (!tracked || ageTracker > MAX_DEPLOY_MS) {
          try {
            await acc.undeploy();
            console.log('[HARD-SCAN] ✅ Compte fantôme undeployed: ' + acc.login + ' (id=' + acc.id + ', tracked=' + (tracked ? Math.round(ageTracker/1000)+'s' : 'NON') + ')');
            if (deployTracker[acc.id]) {
              delete deployTracker[acc.id];
              saveTracker();
            }
          } catch(e) {
            console.log('[HARD-SCAN] Erreur undeploy ' + acc.login + ':', e.message);
          }
        }
      }
    }
  } catch(err) {
    console.log('[HARD-SCAN] Erreur:', err.message);
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

// ─── INIT WATCHDOG ULTRA-RENFORCÉ ─────────────────────────────────
// Au démarrage : recharge le tracker depuis le fichier (survit aux crashs)
deployTracker = loadTracker();

if (metaApi) {
  // Watchdog interne : check le tracker toutes les 30s (était 60s)
  setInterval(watchdogCheck, WATCHDOG_INTERVAL);

  // Boot scan : 30s après le démarrage (laisse MetaApi se stabiliser)
  setTimeout(watchdogBootScan, 30 * 1000);

  // HARD SCAN : filet de sécurité ultime, scan complet toutes les 10 min
  // Détecte les comptes "fantômes" (deployed mais hors du tracker)
  setInterval(hardScanComptesFantomes, HARD_SCAN_INTERVAL);

  // Sauvegarde le tracker toutes les 10s (au cas où le serveur crashe)
  setInterval(saveTracker, 10 * 1000);

  console.log('[WATCHDOG] Multi-couches actif : interne 30s, hard scan 10min, max ' + (MAX_DEPLOY_MS/1000) + 's deployed');
}

// ─── CHIFFREMENT AES-256 POUR CREDENTIALS MT5 ───────────────────────
// La cle est dans MT5_ENCRYPT_KEY (32 chars) — DOIT etre dans .env / Render
// ✅ FIX BUG CRITIQUE : si MT5_ENCRYPT_KEY manquant → crash immédiat au démarrage
// Avant : fallback silencieux sur clé = 32 zéros → sécurité nulle
if (!process.env.MT5_ENCRYPT_KEY && process.env.NODE_ENV === 'production') {
  console.error('[CRYPTO] FATAL : MT5_ENCRYPT_KEY absent du .env en production — arrêt du serveur');
  process.exit(1);
}
const ENCRYPT_KEY = (process.env.MT5_ENCRYPT_KEY || 'dev-only-key-NOT-for-production!!').padEnd(32, '0').slice(0, 32);
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
// ✅ FIX BUG : multer sans limite → upload de Go possible (DoS, coûts stockage)
const MULTER_LIMITS = { fileSize: 15 * 1024 * 1024 }; // 15 MB max par image
const upload = multer({ dest: 'uploads/', limits: MULTER_LIMITS });
const uploadMulti = multer({ dest: 'uploads/', limits: MULTER_LIMITS });
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const BASE_URL = process.env.BASE_URL || 'http://localhost:' + port;

const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  secure: false, // STARTTLS sur port 587 (pas SSL direct)
  auth: {
    user: process.env.BREVO_USER,
    pass: process.env.BREVO_PASS
  },
  // ✅ FIX DÉLIVRABILITÉ : options pour Render (proxy TLS) + timeout raisonnable
  tls: { rejectUnauthorized: false },
  pool: true,          // connexions réutilisées (plus efficace pour broadcast)
  maxConnections: 3,   // max 3 connexions simultanées vers Brevo
  rateDelta: 1000,     // espace les envois d'au moins 1s
  rateLimit: 3         // max 3 emails/s (respect des limites Brevo free)
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
  const expired = new Date() > new Date(user.paidUntil);
  // Log uniquement quand ça expire (utile pour le debug admin)
  if (expired) {
    const expiredAt = new Date(user.paidUntil).toISOString();
    console.log('[PAYMENT] Abonnement expiré pour ' + user.email + ' (paidUntil: ' + expiredAt + ')');
  }
  return expired;
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

function calculerLots(capital, risquePct, slPips, instrument, slDistanceDollars = null) {
  if (!capital || !slPips || slPips <= 0) return null;
  const montantRisque = capital * risquePct / 100;
  const inst = (instrument || '').toUpperCase();

  // ─── DETECTION INSTRUMENT + NORMALISATION DU SL ─────────────────
  // Si slDistanceDollars est fourni, on l'utilise DIRECTEMENT (= |entrée - SL|).
  // Sinon, fallback sur les heuristiques sur slPips (moins fiable).
  let valeurMouvementParLot; // = combien $ je perds/gagne pour le SL complet sur 1 lot
  let slEnDollars; // SL converti en dollars (mouvement de prix)

  if (inst.includes('XAU') || inst.includes('GOLD')) {
    // Pour XAUUSD : 1 lot = 100 onces. 1$ de mouvement = 100$ de P&L par lot.
    if (slDistanceDollars !== null && slDistanceDollars > 0) {
      // ✅ SOURCE FIABLE : distance directe en dollars (|entrée - SL|)
      slEnDollars = slDistanceDollars;
    } else if (slPips < 30) {
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
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0
      ? slDistanceDollars
      : (slPips < 5 ? slPips : slPips / 10);
    valeurMouvementParLot = 50;
  } else if (inst.includes('JPY')) {
    // Forex JPY : 1 pip = 0.01, 1 lot = ~$9 par pip
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0
      ? slDistanceDollars
      : slPips * 0.01;
    valeurMouvementParLot = 909; // ~$9.09 par pip * 100 pips/dollar
  } else if (inst.includes('NAS') || inst.includes('NDX') || inst.includes('US100')) {
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0 ? slDistanceDollars : slPips;
    valeurMouvementParLot = 1;
  } else if (inst.includes('SPX') || inst.includes('SP500') || inst.includes('US500')) {
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0 ? slDistanceDollars : slPips;
    valeurMouvementParLot = 1;
  } else {
    // Forex standard : 1 pip = 0.0001, 1 lot = ~$10 par pip
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0
      ? slDistanceDollars
      : slPips * 0.0001;
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
// 🛡️ DÉTECTION DE TENDANCE ROBUSTE (multi-méthode + vote majoritaire)
// ═══════════════════════════════════════════════════════════════════
// 5 indicateurs INDÉPENDANTS, vote majoritaire 3+/5 pour valider tendance.
// Tightened : seuils stricts pour éviter faux positifs sur marché choppy.

function calculerPenteMA(candles, periode, span = 5) {
  if (!candles || candles.length < periode + span) return 0;
  const ma_now = calculerMA(candles, periode);
  const ma_past = calculerMA(candles.slice(0, -span), periode);
  if (ma_now === null || ma_past === null) return 0;
  return ma_now - ma_past;
}

function calculerADX(candles, periode = 14) {
  if (!candles || candles.length < periode + 1) return null;
  let trSum = 0, dmPlusSum = 0, dmMinusSum = 0;
  for (let i = candles.length - periode; i < candles.length; i++) {
    const c = candles[i], p = candles[i - 1];
    const tr = Math.max(c.high - c.low, Math.abs(c.high - p.close), Math.abs(c.low - p.close));
    const upMove = c.high - p.high;
    const downMove = p.low - c.low;
    const dmPlus = (upMove > downMove && upMove > 0) ? upMove : 0;
    const dmMinus = (downMove > upMove && downMove > 0) ? downMove : 0;
    trSum += tr; dmPlusSum += dmPlus; dmMinusSum += dmMinus;
  }
  if (trSum === 0) return null;
  const diPlus = (dmPlusSum / trSum) * 100;
  const diMinus = (dmMinusSum / trSum) * 100;
  const dx = (Math.abs(diPlus - diMinus) / (diPlus + diMinus || 1)) * 100;
  return { adx: dx, diPlus, diMinus };
}

// Calcule la volatilité (écart-type des closes sur N bougies, normalisée)
function calculerVolatilite(candles, n = 30) {
  if (!candles || candles.length < n) return 0;
  const closes = candles.slice(-n).map(c => c.close);
  const mean = closes.reduce((a, b) => a + b, 0) / n;
  const variance = closes.reduce((s, c) => s + (c - mean) ** 2, 0) / n;
  return Math.sqrt(variance) / mean; // CV (coefficient de variation)
}

function detecterTendanceRobuste(candles) {
  if (!candles || candles.length < 50) {
    return { trend: 'RANGE', confidence: 0, votes: {}, debug: { error: 'Pas assez de bougies' } };
  }

  let votesBullish = 0, votesBearish = 0;
  const debug = {};
  const votes = {};

  // ─── PRÉ-CHECK : marché trop choppy → RANGE direct ──────────────
  // Si la volatilité est élevée ET que les bougies oscillent fortement,
  // les méthodes peuvent voter dans tous les sens. Le pré-check empêche
  // de détecter une "tendance" fictive dans un marché chaotique.
  const cv = calculerVolatilite(candles, 30);
  const closes = candles.slice(-30).map(c => c.close);
  const minClose = Math.min(...closes);
  const maxClose = Math.max(...closes);
  const range = maxClose - minClose;
  const lastVsRange = (candles[candles.length-1].close - minClose) / (range || 1);
  // Si on est entre 30% et 70% du range et que la volatilité est haute → choppy
  const isChoppy = cv > 0.005 && lastVsRange > 0.30 && lastVsRange < 0.70;
  debug.preCheck = { cv: +cv.toFixed(4), lastVsRange: +lastVsRange.toFixed(2), isChoppy };

  // ─── M1 : MA20 vs MA50 + PENTE MA50 (renforcée) ─────────────────
  // Pente significative = > 0.1% du prix par bougie sur 5 bougies
  const ma20 = calculerMA(candles, 20);
  const ma50 = calculerMA(candles, 50);
  const penteMA50 = calculerPenteMA(candles, 50, 5);
  const lastClose = candles[candles.length - 1].close;
  const seuilPente = lastClose * 0.0005; // 0.05% du prix
  debug.method1 = { ma20, ma50, penteMA50: +penteMA50.toFixed(2), seuilPente: +seuilPente.toFixed(2) };

  if (ma20 !== null && ma50 !== null) {
    if (ma20 > ma50 && penteMA50 > seuilPente) { votesBullish++; votes.m1 = 'BULL'; }
    else if (ma20 < ma50 && penteMA50 < -seuilPente) { votesBearish++; votes.m1 = 'BEAR'; }
    else votes.m1 = 'NEUTRAL';
  }

  // ─── M2 : POSITION PRIX vs MA50 (% sur 15 dernières bougies) ────
  // Renforcé : 80% au lieu de 70% pour éviter faux positifs sur range
  if (ma50 !== null) {
    const dernieres15 = candles.slice(-15);
    const auDessus = dernieres15.filter(c => c.close > ma50).length;
    const enDessous = dernieres15.filter(c => c.close < ma50).length;
    debug.method2 = { auDessus, enDessous, total: 15 };
    if (auDessus >= 12) { votesBullish++; votes.m2 = 'BULL'; }      // 80%
    else if (enDessous >= 12) { votesBearish++; votes.m2 = 'BEAR'; }
    else votes.m2 = 'NEUTRAL';
  }

  // ─── M3 : SWINGS HH/HL vs LH/LL (renforcé : exige 3+ swings concordants) ─
  // detecterStructure du module ICT, mais on regarde la cohérence des 3 derniers
  try {
    const struct = detecterStructure(candles, 3);
    debug.method3 = { trend: struct.trend, event: struct.event?.type || null };
    // Plus strict : vote uniquement sur UP/DOWN clairs (jamais EXPANSION ni RANGE)
    if (struct.trend === 'UP') { votesBullish++; votes.m3 = 'BULL'; }
    else if (struct.trend === 'DOWN') { votesBearish++; votes.m3 = 'BEAR'; }
    else votes.m3 = 'NEUTRAL';
  } catch(e) {
    debug.method3 = { error: e.message }; votes.m3 = 'NEUTRAL';
  }

  // ─── M4 : ADX directionnel (seuil 25 au lieu de 20) ─────────────
  const adxData = calculerADX(candles, 14);
  if (adxData) {
    debug.method4 = {
      adx: +adxData.adx.toFixed(1), diPlus: +adxData.diPlus.toFixed(1), diMinus: +adxData.diMinus.toFixed(1)
    };
    if (adxData.adx >= 25) {
      // Exiger un écart significatif entre DI+ et DI-
      const ecart = Math.abs(adxData.diPlus - adxData.diMinus);
      const ecartMin = (adxData.diPlus + adxData.diMinus) * 0.15; // 15% d'écart relatif
      if (adxData.diPlus > adxData.diMinus && ecart > ecartMin) { votesBullish++; votes.m4 = 'BULL'; }
      else if (adxData.diMinus > adxData.diPlus && ecart > ecartMin) { votesBearish++; votes.m4 = 'BEAR'; }
      else votes.m4 = 'NEUTRAL';
    } else {
      votes.m4 = 'NEUTRAL';
    }
  }

  // ─── M5 : % BOUGIES + AMPLITUDE ─────────────────────────────────
  // Renforcé : pas seulement le nombre, mais aussi l'amplitude moyenne
  const dernieres30 = candles.slice(-30);
  let bullCount = 0, bearCount = 0;
  let bullAmplitude = 0, bearAmplitude = 0;
  dernieres30.forEach(c => {
    const corps = Math.abs(c.close - c.open);
    if (c.close > c.open) { bullCount++; bullAmplitude += corps; }
    else if (c.close < c.open) { bearCount++; bearAmplitude += corps; }
  });
  // Le côté qui a les bougies + grosses amplitudes gagne
  const bullScore = bullCount * (bullAmplitude / Math.max(bullCount, 1));
  const bearScore = bearCount * (bearAmplitude / Math.max(bearCount, 1));
  debug.method5 = { bullCount, bearCount, bullScore: +bullScore.toFixed(1), bearScore: +bearScore.toFixed(1) };

  // Vote uniquement si dominance nette (1.5x l'autre côté)
  if (bullCount >= 18 && bullScore > bearScore * 1.5) { votesBullish++; votes.m5 = 'BULL'; }
  else if (bearCount >= 18 && bearScore > bullScore * 1.5) { votesBearish++; votes.m5 = 'BEAR'; }
  else votes.m5 = 'NEUTRAL';

  // ─── DÉCISION FINALE ─────────────────────────────────────────────
  // Si choppy ET pas de majorité écrasante → RANGE forcé
  let trend = 'RANGE';
  let confidence = 0;
  if (votesBullish >= 3 && votesBullish > votesBearish && (!isChoppy || votesBullish >= 4)) {
    trend = 'BULLISH';
    confidence = votesBullish;
  } else if (votesBearish >= 3 && votesBearish > votesBullish && (!isChoppy || votesBearish >= 4)) {
    trend = 'BEARISH';
    confidence = votesBearish;
  } else {
    confidence = Math.max(votesBullish, votesBearish);
  }

  return { trend, confidence, votes, votesBullish, votesBearish, debug };
}



// ═══════════════════════════════════════════════════════════════════
// 📊 INDICATEURS TECHNIQUES — INJECTION DANS LE PROMPT
// ═══════════════════════════════════════════════════════════════════
// Calcule RSI + MA20 + MA50 sur H1, M15, M5 et formatte un bloc texte
// que l'IA reçoit AVANT de proposer son trade. Comme ça elle voit les
// indicateurs réels (pas devinés sur les screens) et propose un setup
// cohérent avec eux.

// ═══════════════════════════════════════════════════════════════════
// 🧩 MODULE INLINÉ : ICT DETECTION (DOL, P/D, MSS, kill zones, OB validation)
// ═══════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════
// 🎯 ict-detection.js — Concepts ICT/SMC manquants à AI-Mazza
// ═══════════════════════════════════════════════════════════════════
// À placer dans le projet, à côté de server.js
// Importé via : const ict = require('./ict-detection');
//
// Ce module est PURE FONCTION (pas d'I/O), tu lui passes des bougies
// MetaAPI il te rend des objets analysables. Aucun appel réseau.
// ═══════════════════════════════════════════════════════════════════

// ─── HELPERS ────────────────────────────────────────────────────────

// Détecte les swings (pivot highs/lows) avec un lookback configurable
// Un swing high = bougie dont le high est > aux N bougies avant et après
function detecterSwings(candles, lookback = 3) {
  const swings = { highs: [], lows: [] };
  if (!candles || candles.length < lookback * 2 + 1) return swings;

  for (let i = lookback; i < candles.length - lookback; i++) {
    const c = candles[i];
    let isSwingHigh = true, isSwingLow = true;
    for (let j = 1; j <= lookback; j++) {
      if (candles[i - j].high >= c.high || candles[i + j].high >= c.high) isSwingHigh = false;
      if (candles[i - j].low <= c.low || candles[i + j].low <= c.low) isSwingLow = false;
    }
    if (isSwingHigh) swings.highs.push({ price: c.high, index: i, time: c.time });
    if (isSwingLow)  swings.lows.push({ price: c.low,  index: i, time: c.time });
  }
  return swings;
}

// ATR simple pour buffer dynamique
function calculerATR(candles, period = 14) {
  if (!candles || candles.length < period + 1) return 0;
  let sum = 0;
  for (let i = candles.length - period; i < candles.length; i++) {
    const c = candles[i], p = candles[i - 1];
    const tr = Math.max(c.high - c.low, Math.abs(c.high - p.close), Math.abs(c.low - p.close));
    sum += tr;
  }
  return sum / period;
}

// ─── 1. DEALING RANGE + PREMIUM/DISCOUNT ────────────────────────────
// Le dealing range = du dernier swing high majeur au dernier swing low majeur
// Equilibrium = milieu (50%). Au-dessus = premium (zone SELL), en-dessous = discount (zone BUY)
function getDealingRange(candles, lookback = 5) {
  if (!candles || candles.length < 5) return null;
  const swings = detecterSwings(candles, lookback);

  // Si on a des swings clairs, on les utilise. Sinon fallback : high/low récents
  let high, low, lastHighTime, lastLowTime;
  if (swings.highs.length && swings.lows.length) {
    const lastHigh = swings.highs[swings.highs.length - 1];
    const lastLow  = swings.lows[swings.lows.length - 1];
    high = lastHigh.price;
    low  = lastLow.price;
    lastHighTime = lastHigh.time;
    lastLowTime = lastLow.time;
  } else {
    // Fallback : high/low des 30 dernières bougies (range récent)
    const recent = candles.slice(-Math.min(30, candles.length));
    let hC = recent[0], lC = recent[0];
    recent.forEach(c => {
      if (c.high > hC.high) hC = c;
      if (c.low < lC.low) lC = c;
    });
    high = hC.high;
    low = lC.low;
    lastHighTime = hC.time;
    lastLowTime = lC.time;
  }

  const range = high - low;
  if (range <= 0) return null;

  const equilibrium = (high + low) / 2;
  // Niveaux OTE (Optimal Trade Entry) : 62%, 70.5%, 79%
  const ote62_buy = low + range * 0.38;   // pour BUY en discount
  const ote70_buy = low + range * 0.295;
  const ote79_buy = low + range * 0.21;
  const ote62_sell = high - range * 0.38; // pour SELL en premium
  const ote70_sell = high - range * 0.295;
  const ote79_sell = high - range * 0.21;

  const currentPrice = candles[candles.length - 1].close;
  // Clamp positionPct entre -10% et 110% pour éviter les valeurs aberrantes
  const rawPct = ((currentPrice - low) / range) * 100;
  const positionPct = Math.max(-10, Math.min(110, rawPct));

  let zone;
  if (positionPct < 45) zone = 'DISCOUNT';
  else if (positionPct > 55) zone = 'PREMIUM';
  else zone = 'EQUILIBRIUM';

  return {
    high, low, range, equilibrium,
    currentPrice,
    positionPct: Math.round(positionPct * 10) / 10,
    zone,
    ote: {
      buyZone: { from: low, to: equilibrium, sweet: [ote62_buy, ote70_buy, ote79_buy] },
      sellZone: { from: equilibrium, to: high, sweet: [ote62_sell, ote70_sell, ote79_sell] }
    },
    lastSwingHighTime: lastHighTime,
    lastSwingLowTime: lastLowTime
  };
}

// ─── 2. MARKET STRUCTURE SHIFT (MSS) / BREAK OF STRUCTURE (BOS) ─────
// BOS = continuation de tendance (cassure du dernier high en uptrend)
// MSS = renversement (cassure du dernier high après une tendance baissière)
function detecterStructure(candles, lookback = 3) {
  const swings = detecterSwings(candles, lookback);
  // Si pas assez de swings, retourner une structure par défaut RANGE
  if (swings.highs.length < 3 || swings.lows.length < 3) {
    if (!candles || !candles.length) return null;
    const lastHigh = swings.highs[swings.highs.length - 1]?.price || candles[candles.length - 1].high;
    const lastLow = swings.lows[swings.lows.length - 1]?.price || candles[candles.length - 1].low;
    return { trend: 'RANGE', event: null, dernierHigh: lastHigh, dernierLow: lastLow, force: 0 };
  }

  // FIX problème 2 : on regarde les 3 derniers swings (pas 2) pour stabilité
  // Tendance UP confirmée si swings highs CONSÉCUTIVEMENT haussiers ET lows aussi
  // Tendance DOWN confirmée si swings highs CONSÉCUTIVEMENT baissiers ET lows aussi
  const recentHighs = swings.highs.slice(-3);
  const recentLows  = swings.lows.slice(-3);
  const last = candles[candles.length - 1];

  // Compter HH/HL consécutifs (force haussière)
  let hhCount = 0, hlCount = 0;
  for (let i = 1; i < recentHighs.length; i++) {
    if (recentHighs[i].price > recentHighs[i-1].price) hhCount++;
  }
  for (let i = 1; i < recentLows.length; i++) {
    if (recentLows[i].price > recentLows[i-1].price) hlCount++;
  }
  // Compter LH/LL consécutifs (force baissière)
  let lhCount = 0, llCount = 0;
  for (let i = 1; i < recentHighs.length; i++) {
    if (recentHighs[i].price < recentHighs[i-1].price) lhCount++;
  }
  for (let i = 1; i < recentLows.length; i++) {
    if (recentLows[i].price < recentLows[i-1].price) llCount++;
  }

  // Force = somme des concordances (max 4 avec 3 swings)
  const forceUp = hhCount + hlCount;
  const forceDown = lhCount + llCount;

  let trend, force;
  // Exiger au moins 2 concordances (sur 4 max possibles) pour valider une tendance
  if (forceUp >= 2 && forceDown <= 1) { trend = 'UP'; force = forceUp; }
  else if (forceDown >= 2 && forceUp <= 1) { trend = 'DOWN'; force = forceDown; }
  else if (forceUp >= 2 && forceDown >= 2) { trend = 'EXPANSION'; force = Math.max(forceUp, forceDown); }
  else { trend = 'RANGE'; force = 0; }

  // BOS / MSS détection : la dernière clôture casse un swing récent ?
  const dernierHigh = recentHighs[recentHighs.length - 1];
  const dernierLow  = recentLows[recentLows.length - 1];

  let event = null;
  if (last.close > dernierHigh.price && trend === 'DOWN') {
    event = { type: 'MSS_BULLISH', niveau: dernierHigh.price, message: 'Renversement haussier confirmé (cassure du dernier swing high après tendance baissière)' };
  } else if (last.close < dernierLow.price && trend === 'UP') {
    event = { type: 'MSS_BEARISH', niveau: dernierLow.price, message: 'Renversement baissier confirmé (cassure du dernier swing low après tendance haussière)' };
  } else if (last.close > dernierHigh.price && trend === 'UP') {
    event = { type: 'BOS_BULLISH', niveau: dernierHigh.price, message: 'Continuation haussière (cassure du précédent high)' };
  } else if (last.close < dernierLow.price && trend === 'DOWN') {
    event = { type: 'BOS_BEARISH', niveau: dernierLow.price, message: 'Continuation baissière (cassure du précédent low)' };
  }

  return { trend, event, dernierHigh: dernierHigh.price, dernierLow: dernierLow.price, force: force || 0 };
}

// ─── 3. LIQUIDITY DETECTION (equal highs/lows + asian range + DOL) ──
// Equal highs/lows = liquidité accumulée (stops des traders) → cible probable
function detecterLiquidite(candles, tolerancePct = 0.0008) {
  if (!candles || candles.length < 10) return { equalHighs: [], equalLows: [] };

  const equalHighs = [], equalLows = [];
  const swings = detecterSwings(candles, 2);

  // Cherche des swings highs/lows dans une tolérance de 0.08% (8 pips sur XAU à 4700)
  for (let i = 0; i < swings.highs.length - 1; i++) {
    for (let j = i + 1; j < swings.highs.length; j++) {
      const a = swings.highs[i].price, b = swings.highs[j].price;
      if (Math.abs(a - b) / a < tolerancePct) {
        equalHighs.push({ price: (a + b) / 2, count: 2, levels: [a, b] });
      }
    }
  }
  for (let i = 0; i < swings.lows.length - 1; i++) {
    for (let j = i + 1; j < swings.lows.length; j++) {
      const a = swings.lows[i].price, b = swings.lows[j].price;
      if (Math.abs(a - b) / a < tolerancePct) {
        equalLows.push({ price: (a + b) / 2, count: 2, levels: [a, b] });
      }
    }
  }

  // Dédupliquer (garder le plus haut prix unique)
  const dedupe = (arr) => {
    const seen = new Set();
    return arr.filter(x => {
      const key = x.price.toFixed(1);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  };

  return { equalHighs: dedupe(equalHighs).slice(-3), equalLows: dedupe(equalLows).slice(-3) };
}

// Range asiatique (00h-07h UTC) = key levels du jour
// FIX BUG 10 : gère weekend / jours fériés (remonte à la dernière session valide)
function getAsianRange(candlesM15) {
  if (!candlesM15 || !candlesM15.length) return null;

  const now = new Date();
  // Si on est dimanche (0) ou samedi (6), retourner null
  // (les marchés Forex sont fermés, le range "asiatique" du jour n'a pas de sens)
  const dayOfWeek = now.getUTCDay();
  if (dayOfWeek === 0 || dayOfWeek === 6) return null;

  // Lundi avant ouverture asiat (avant 00h UTC) → return null pour éviter
  // un range basé sur la session de vendredi
  if (dayOfWeek === 1 && now.getUTCHours() < 7) {
    // On accepte uniquement si on a au moins 5 bougies depuis 00h UTC
    const today = new Date(); today.setUTCHours(0, 0, 0, 0);
    const since = candlesM15.filter(c => new Date(c.time).getTime() >= today.getTime());
    if (since.length < 5) return null;
  }

  // Boucle sur les 5 derniers jours pour trouver une session asiat valide
  for (let dayOffset = 0; dayOffset <= 5; dayOffset++) {
    const targetDay = new Date(now);
    targetDay.setUTCDate(targetDay.getUTCDate() - dayOffset);
    targetDay.setUTCHours(0, 0, 0, 0);
    // Skip weekend
    const dow = targetDay.getUTCDay();
    if (dow === 0 || dow === 6) continue;

    const asianStart = targetDay.getTime();
    const asianEnd = asianStart + 7 * 3600 * 1000;

    const asianCandles = candlesM15.filter(c => {
      const t = new Date(c.time).getTime();
      return t >= asianStart && t < asianEnd;
    });

    if (asianCandles.length >= 5) {
      const high = Math.max(...asianCandles.map(c => c.high));
      const low = Math.min(...asianCandles.map(c => c.low));
      return {
        high, low,
        mid: (high + low) / 2,
        candleCount: asianCandles.length,
        dayOffset // 0 = aujourd'hui, 1 = hier (utile pour debug)
      };
    }
  }
  return null;
}

// Draw on Liquidity = la cible la plus probable du prix
// Logique : cherche la pool de liquidité la plus proche dans le sens du momentum
function getDrawOnLiquidity(candles, structure, asianRange, equalHL) {
  if (!structure) return null;
  const last = candles[candles.length - 1];
  const price = last.close;

  const cibles = [];

  // Equal highs au-dessus du prix = sell-side liquidity (bullish target)
  equalHL.equalHighs.forEach(eh => {
    if (eh.price > price) cibles.push({ price: eh.price, type: 'EQH', side: 'BULLISH', distance: eh.price - price });
  });
  // Equal lows en-dessous = buy-side liquidity (bearish target)
  equalHL.equalLows.forEach(el => {
    if (el.price < price) cibles.push({ price: el.price, type: 'EQL', side: 'BEARISH', distance: price - el.price });
  });

  // Asian high/low si pas encore sweep
  if (asianRange) {
    if (asianRange.high > price) cibles.push({ price: asianRange.high, type: 'ASIAN_HIGH', side: 'BULLISH', distance: asianRange.high - price });
    if (asianRange.low  < price) cibles.push({ price: asianRange.low,  type: 'ASIAN_LOW',  side: 'BEARISH', distance: price - asianRange.low  });
  }

  // Dernier swing high/low récent
  if (structure.dernierHigh > price) cibles.push({ price: structure.dernierHigh, type: 'PREVIOUS_HIGH', side: 'BULLISH', distance: structure.dernierHigh - price });
  if (structure.dernierLow  < price) cibles.push({ price: structure.dernierLow,  type: 'PREVIOUS_LOW',  side: 'BEARISH', distance: price - structure.dernierLow });

  if (!cibles.length) return null;

  // Tri par distance croissante : la plus proche = cible immédiate
  cibles.sort((a, b) => a.distance - b.distance);

  // Bias directionnel : si tendance UP, on privilégie les cibles BULLISH
  const biasUp = structure.trend === 'UP' || (structure.event && structure.event.type.includes('BULLISH'));
  const biasDown = structure.trend === 'DOWN' || (structure.event && structure.event.type.includes('BEARISH'));

  const cibleAlignée = cibles.find(c =>
    (biasUp && c.side === 'BULLISH') || (biasDown && c.side === 'BEARISH')
  );

  return {
    cible: cibleAlignée || cibles[0],
    toutes: cibles.slice(0, 4),
    biasDirectionnel: biasUp ? 'BULLISH' : (biasDown ? 'BEARISH' : 'NEUTRAL')
  };
}

// ─── 4. LIQUIDITY SWEEP DETECTION (a-t-il déjà été pris ?) ──────────
// Un sweep = mèche qui dépasse un niveau de liquidité PUIS clôture de l'autre côté
function detecterSweepRécent(candles, niveau, type, lookback = 5) {
  // type = 'HIGH' (sweep d'un niveau au-dessus) ou 'LOW'
  if (!candles || candles.length < lookback) return null;
  const recent = candles.slice(-lookback);

  for (const c of recent) {
    if (type === 'HIGH' && c.high > niveau && c.close < niveau) {
      return { swept: true, time: c.time, wickPenetration: c.high - niveau };
    }
    if (type === 'LOW' && c.low < niveau && c.close > niveau) {
      return { swept: true, time: c.time, wickPenetration: niveau - c.low };
    }
  }
  return { swept: false };
}

// ─── 5. ORDER BLOCK MITIGATION (validation de l'OB) ─────────────────
// Un OB est "fort" s'il a été créé avec un déplacement (FVG dans la foulée)
// et "valide" tant qu'il n'a pas été retesté complètement (au-delà du milieu)
function validerOB(ob, candles) {
  if (!candles || candles.length < 5) return { ...ob, qualite: 'UNKNOWN' };

  const obIndex = candles.findIndex(c => c.time === ob.time);
  if (obIndex === -1 || obIndex >= candles.length - 3) return { ...ob, qualite: 'UNKNOWN' };

  // Y a-t-il une FVG dans les 3 bougies suivantes ? → OB de qualité (avec displacement)
  let hasDisplacement = false;
  for (let i = obIndex + 1; i < Math.min(obIndex + 4, candles.length); i++) {
    if (i >= 2) {
      const c1 = candles[i - 2], c3 = candles[i];
      if (c3.low > c1.high || c3.high < c1.low) { hasDisplacement = true; break; }
    }
  }

  // Le prix est-il déjà retourné dans la zone ? Si oui, mitigated
  const milieuOB = (ob.zone.high + ob.zone.low) / 2;
  let mitigated = false;
  for (let i = obIndex + 1; i < candles.length; i++) {
    const c = candles[i];
    if (c.low <= milieuOB && c.high >= milieuOB) { mitigated = true; break; }
  }

  let qualite;
  if (hasDisplacement && !mitigated) qualite = 'HIGH';     // OB frais avec displacement = top
  else if (hasDisplacement && mitigated) qualite = 'MEDIUM'; // déjà retesté mais bon départ
  else if (!hasDisplacement) qualite = 'LOW';                // pas de displacement = simple bougie

  return { ...ob, qualite, hasDisplacement, mitigated };
}

// ─── 6. KILL ZONES ICT (granulaire) ─────────────────────────────────
// Heures Paris (CET/CEST). Plus fin que ce qu'il y a dans server.js actuel.
function getKillZone(date = new Date()) {
  const hourParis = parseInt(date.toLocaleString('fr-FR', { timeZone: 'Europe/Paris', hour: '2-digit', hour12: false }));
  const minute = parseInt(date.toLocaleString('fr-FR', { timeZone: 'Europe/Paris', minute: '2-digit' }));

  // London Open KZ : 08h-11h Paris
  if (hourParis >= 8 && hourParis < 11) return { name: 'LONDON_OPEN', boost: 1, qualite: 'HIGH' };
  // NY AM KZ : 13h-15h Paris
  if (hourParis >= 13 && hourParis < 15) return { name: 'NY_AM', boost: 1, qualite: 'HIGH' };
  // ⭐ Silver Bullet AM : 16h-17h Paris (10h-11h NY) — LE meilleur window
  if (hourParis === 16) return { name: 'SILVER_BULLET_AM', boost: 2, qualite: 'A_PLUS' };
  // London Close : 17h-18h Paris
  if (hourParis >= 17 && hourParis < 18) return { name: 'LONDON_CLOSE', boost: 1, qualite: 'MEDIUM' };
  // ⭐ Silver Bullet PM : 20h-21h Paris (14h-15h NY)
  if (hourParis === 20) return { name: 'SILVER_BULLET_PM', boost: 1, qualite: 'HIGH' };
  // Asian KZ (faible mais pour le range) : 02h-05h Paris
  if (hourParis >= 2 && hourParis < 5) return { name: 'ASIAN', boost: 0, qualite: 'LOW' };
  // Pré-asiat / fin de journée : 18h-20h
  if (hourParis >= 18 && hourParis < 20) return { name: 'NY_PM', boost: 0, qualite: 'MEDIUM' };

  return { name: 'OFF_HOURS', boost: -1, qualite: 'AVOID' };
}

// ─── 7. SCORING SYSTÈME (additif transparent) ───────────────────────
// Remplace le score 0-10 opaque par un système à points expliqué
function scoreSetup(features) {
  // features = { hasDOL, premiumDiscountAligned, mssOrBosAligned, obQuality, fvgPresent,
  //              crtKasperConfirmed, killZoneBoost, newsClean, structureH1Aligned, sweepRecent }
  const points = [];

  if (features.hasDOL)                points.push({ pts: 2, raison: 'Cible DOL identifiée' });
  if (features.premiumDiscountAligned) points.push({ pts: 2, raison: 'Zone Premium/Discount alignée' });
  if (features.mssOrBosAligned)        points.push({ pts: 2, raison: 'MSS/BOS aligné avec direction' });
  if (features.obQuality === 'HIGH')   points.push({ pts: 1.5, raison: 'OB haute qualité (displacement, non mitigé)' });
  else if (features.obQuality === 'MEDIUM') points.push({ pts: 0.75, raison: 'OB moyen' });
  if (features.fvgPresent)             points.push({ pts: 1, raison: 'FVG en confluence' });
  if (features.crtKasperConfirmed)     points.push({ pts: 2, raison: 'CRT Kasper confirmé' });
  if (features.killZoneBoost > 0)      points.push({ pts: features.killZoneBoost, raison: `Kill zone ${features.killZoneName}` });
  if (features.newsClean)              points.push({ pts: 0.5, raison: 'Pas de news rouge dans 30min' });
  if (features.structureH1Aligned)     points.push({ pts: 1, raison: 'H1 aligné' });
  if (features.sweepRecent)            points.push({ pts: 1.5, raison: 'Sweep de liquidité récent' });

  // Pénalités
  if (features.killZoneBoost < 0)      points.push({ pts: -2, raison: 'Hors kill zone' });
  if (features.consecutiveLosses >= 2) points.push({ pts: -1, raison: '2+ pertes consécutives (anti-tilt)' });

  const total = points.reduce((s, p) => s + p.pts, 0);
  return {
    total: Math.round(total * 10) / 10,
    decomposition: points,
    decision: total >= 7 ? 'TRADE' : (total >= 5 ? 'BORDERLINE' : 'NE_PAS_TRADER')
  };
}

// ─── 8. ANALYSE COMPLÈTE (fonction principale à appeler) ────────────
async function analyseComplete(candlesM15, candlesH1, candlesM5) {
  const structureM15 = detecterStructure(candlesM15, 3);
  const structureH1  = candlesH1 ? detecterStructure(candlesH1, 2) : null;
  const dealingRange = getDealingRange(candlesH1 || candlesM15, 5);
  const liquidite    = detecterLiquidite(candlesM15);
  const asianRange   = getAsianRange(candlesM15);
  const dol          = getDrawOnLiquidity(candlesM15, structureM15, asianRange, liquidite);
  const killZone     = getKillZone();
  const atr          = calculerATR(candlesM15, 14);

  return {
    structureM15,
    structureH1,
    dealingRange,
    liquidite,
    asianRange,
    drawOnLiquidity: dol,
    killZone,
    atr,
    bufferSL: Math.max(atr * 0.3, 3) // buffer SL dynamique : 30% ATR, min 3$ sur XAU
  };
}

// ─── 9. FORMATTAGE POUR LE PROMPT ───────────────────────────────────
// Génère le bloc texte à injecter dans le prompt envoyé à Claude
function formatPourPrompt(analyse) {
  let txt = '\n═══════════════════════════════════════════════════════════════\n';
  txt += '🧠 ANALYSE ICT ALGORITHMIQUE (calculée sur les vraies bougies)\n';
  txt += '═══════════════════════════════════════════════════════════════\n';

  // Dealing range
  if (analyse.dealingRange) {
    const dr = analyse.dealingRange;
    txt += `\n📐 DEALING RANGE H1 :\n`;
    txt += `  - High: ${dr.high.toFixed(2)} | Low: ${dr.low.toFixed(2)} | Equilibrium 50%: ${dr.equilibrium.toFixed(2)}\n`;
    txt += `  - Prix actuel: ${dr.currentPrice.toFixed(2)} (${dr.positionPct}% du range)\n`;
    txt += `  - 🎯 ZONE: **${dr.zone}**\n`;
    if (dr.zone === 'DISCOUNT') {
      txt += `  - ✅ Zone DISCOUNT → favoriser les BUY (OTE: ${dr.ote.buyZone.sweet[0].toFixed(2)} - ${dr.ote.buyZone.sweet[2].toFixed(2)})\n`;
      txt += `  - ❌ NE PAS proposer de SELL en discount sauf MSS très clair\n`;
    } else if (dr.zone === 'PREMIUM') {
      txt += `  - ✅ Zone PREMIUM → favoriser les SELL (OTE: ${dr.ote.sellZone.sweet[2].toFixed(2)} - ${dr.ote.sellZone.sweet[0].toFixed(2)})\n`;
      txt += `  - ❌ NE PAS proposer de BUY en premium sauf MSS très clair\n`;
    } else {
      txt += `  - ⚠️ Zone EQUILIBRIUM (45-55%) → ATTENDRE que le prix sorte vers premium ou discount\n`;
    }
  }

  // Structure
  if (analyse.structureM15) {
    txt += `\n📊 STRUCTURE M15 : ${analyse.structureM15.trend}\n`;
    if (analyse.structureM15.event) {
      txt += `  - 🚨 ÉVÉNEMENT: ${analyse.structureM15.event.type} à ${analyse.structureM15.event.niveau.toFixed(2)}\n`;
      txt += `  - ${analyse.structureM15.event.message}\n`;
    }
    txt += `  - Dernier swing high: ${analyse.structureM15.dernierHigh.toFixed(2)} | swing low: ${analyse.structureM15.dernierLow.toFixed(2)}\n`;
  }
  if (analyse.structureH1) {
    txt += `📊 STRUCTURE H1 : ${analyse.structureH1.trend}`;
    if (analyse.structureH1.event) txt += ` (${analyse.structureH1.event.type})`;
    txt += '\n';
  }

  // Draw on Liquidity
  if (analyse.drawOnLiquidity && analyse.drawOnLiquidity.cible) {
    const c = analyse.drawOnLiquidity.cible;
    txt += `\n🎯 DRAW ON LIQUIDITY (cible directionnelle) :\n`;
    txt += `  - **${c.type}** à ${c.price.toFixed(2)} (${c.side}, distance ${c.distance.toFixed(2)}$)\n`;
    txt += `  - Bias directionnel: ${analyse.drawOnLiquidity.biasDirectionnel}\n`;
    if (analyse.drawOnLiquidity.toutes.length > 1) {
      txt += `  - Autres cibles: ${analyse.drawOnLiquidity.toutes.slice(1).map(x => `${x.type}@${x.price.toFixed(2)}`).join(', ')}\n`;
    }
  }

  // Liquidité (equal highs/lows)
  if (analyse.liquidite.equalHighs.length || analyse.liquidite.equalLows.length) {
    txt += `\n💧 LIQUIDITÉ DÉTECTÉE :\n`;
    if (analyse.liquidite.equalHighs.length) {
      txt += `  - Equal Highs (sell-side liq): ${analyse.liquidite.equalHighs.map(e => e.price.toFixed(2)).join(', ')}\n`;
    }
    if (analyse.liquidite.equalLows.length) {
      txt += `  - Equal Lows (buy-side liq): ${analyse.liquidite.equalLows.map(e => e.price.toFixed(2)).join(', ')}\n`;
    }
  }

  // Range asiatique
  if (analyse.asianRange) {
    txt += `\n🌏 RANGE ASIATIQUE : ${analyse.asianRange.low.toFixed(2)} - ${analyse.asianRange.high.toFixed(2)} (mid ${analyse.asianRange.mid.toFixed(2)})\n`;
  }

  // Kill zone
  txt += `\n⏰ KILL ZONE ACTUELLE : **${analyse.killZone.name}** (qualité: ${analyse.killZone.qualite}, boost: ${analyse.killZone.boost > 0 ? '+' : ''}${analyse.killZone.boost})\n`;
  if (analyse.killZone.name.includes('SILVER_BULLET')) {
    txt += `  - ⭐ Window statistiquement très favorable, accepter score ≥ 7\n`;
  } else if (analyse.killZone.name === 'OFF_HOURS') {
    txt += `  - ⚠️ Hors kill zone → score minimum exigé: 8.5\n`;
  }

  // ATR
  txt += `\n📏 ATR(14) M15: ${analyse.atr.toFixed(2)}$ | Buffer SL recommandé: ${analyse.bufferSL.toFixed(2)}$\n`;

  // ─── DÉTECTION DE CONFLIT CONTEXTUEL (BUG 3) ──────────────────────────
  // Si dealing range et structure pointent dans des directions opposées
  // sans MSS récent, alerter explicitement l'IA pour qu'elle ne trade pas.
  const conflits = [];
  const dr = analyse.dealingRange;
  const struct = analyse.structureM15;
  if (dr && struct) {
    const drFavorBuy = dr.zone === 'DISCOUNT';
    const drFavorSell = dr.zone === 'PREMIUM';
    const structBearish = struct.trend === 'DOWN';
    const structBullish = struct.trend === 'UP';
    const mssRecent = struct.event && (struct.event.type === 'MSS_BULLISH' || struct.event.type === 'MSS_BEARISH');

    if (drFavorBuy && structBearish && !mssRecent) {
      conflits.push(`Zone DISCOUNT (favorise BUY) MAIS structure M15 = DOWN sans MSS_BULLISH récent`);
    }
    if (drFavorSell && structBullish && !mssRecent) {
      conflits.push(`Zone PREMIUM (favorise SELL) MAIS structure M15 = UP sans MSS_BEARISH récent`);
    }
  }
  if (conflits.length > 0) {
    txt += `\n⚠️ CONFLIT CONTEXTUEL DÉTECTÉ :\n`;
    conflits.forEach(c => txt += `  - ${c}\n`);
    txt += `  → Si tu veux quand même trader, exige un setup A+ avec confluence très forte. Sinon NE PAS TRADER.\n`;
  }

  txt += '═══════════════════════════════════════════════════════════════\n';
  return txt;
}


// ═══════════════════════════════════════════════════════════════════
// 🧩 MODULE INLINÉ : TP MANAGEMENT 3-TIER
// ═══════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════
// 🎯 tp-management.js — Gestion TP partiel 3-tier + trailing structurel
// ═══════════════════════════════════════════════════════════════════
// REMPLACE la fonction gererTpPartielsEtBE() de server.js (ligne 1279)
//
// Améliorations vs ancien système :
// 1. 3 paliers (TP1 / TP2 / TP3) au lieu de 1 seul
// 2. Distribution variable selon score du setup
// 3. SL à BE+buffer (pas pile à l'entrée — évite spread/slippage)
// 4. Trailing structurel après TP2 (suit les swings)
// 5. Tracking par positionId avec étapes franchies
// ═══════════════════════════════════════════════════════════════════

// ─── DISTRIBUTION DES VOLUMES SELON LE SCORE ────────────────────────
// La logique : plus le setup est de qualité, plus on garde de runner pour TP2/TP3
// Setup A+ (score≥9) : on a confiance, on laisse courir → 40/30/30
// Setup A (score 7-8) : confiance moyenne, on sécurise plus tôt → 50/30/20
// Setup B (score 6) : limite, on sort vite → 70/30/0
function getDistribution(score) {
  if (score >= 9)      return { tp1: 0.40, tp2: 0.30, tp3: 0.30, mode: 'A_PLUS' };
  if (score >= 7)      return { tp1: 0.50, tp2: 0.30, tp3: 0.20, mode: 'A' };
  if (score >= 6)      return { tp1: 0.70, tp2: 0.30, tp3: 0,    mode: 'B' };
  return                      { tp1: 1.00, tp2: 0,    tp3: 0,    mode: 'C' }; // tout ferme à TP1
}

// ─── BUFFER BE DYNAMIQUE ────────────────────────────────────────────
// Sur XAU avec spread VTMarkets ~30-50 cents, faut au moins 2-3$ de buffer
// pour que le BE soit vraiment profitable (couvrir spread + commission)
function getBufferBE(symbol, atr) {
  const symBase = (symbol || '').toUpperCase();
  if (symBase.includes('XAU')) {
    // 30% de l'ATR avec minimum 2$ et max 5$
    return Math.min(Math.max(atr * 0.3, 2), 5);
  }
  // Forex majeurs : 5 pips de buffer
  if (symBase.match(/EUR|GBP|USD|JPY/)) return 0.0005;
  return Math.max(atr * 0.3, 1);
}

// ─── DERNIER SWING POUR TRAILING ─────────────────────────────────────
// Pour un BUY : SL trailing sous le dernier swing low M5/M15
// Pour un SELL : SL trailing au-dessus du dernier swing high M5/M15
function trouverNiveauTrailing(candles, direction, lookback = 3) {
  if (!candles || candles.length < lookback * 2 + 1) return null;
  const last = candles[candles.length - 1];

  // On parcourt à l'envers pour trouver le swing le plus récent
  for (let i = candles.length - lookback - 1; i >= lookback; i--) {
    const c = candles[i];
    let isSwing = true;
    for (let j = 1; j <= lookback; j++) {
      if (direction === 'BUY' && (candles[i-j].low <= c.low || candles[i+j].low <= c.low)) { isSwing = false; break; }
      if (direction === 'SELL' && (candles[i-j].high >= c.high || candles[i+j].high >= c.high)) { isSwing = false; break; }
    }
    if (isSwing) {
      return direction === 'BUY' ? c.low : c.high;
    }
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// FONCTION PRINCIPALE — remplace gererTpPartielsEtBE()
// ═══════════════════════════════════════════════════════════════════
async function gererTpPartiels3Tier({
  metaApi, db, analysesDb, positionsTrackingDb, creerNotification
}) {
  if (!metaApi) return;
  try {
    const users = await db.findAsync({ 'mt5.metaApiAccountId': { $exists: true } });

    for (const user of users) {
      let deployedHere = false;
      let account = null;
      try {
        account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);

        // ─── FIX : Auto-deploy temporaire si UNDEPLOYED ─────────────
        // Le wrapper TP DOIT pouvoir tourner même si le compte est undeployed,
        // sinon on rate les TP partiels après le timeout du watchdog.
        // On vérifie d'abord s'il y a au moins 1 position via cache léger,
        // puis on deploy seulement si nécessaire.
        if (account.state !== 'DEPLOYED') {
          // Auto-deploy temporaire pour traiter les TP partiels
          try {
            await account.deploy();
            if (typeof trackDeploy === 'function') trackDeploy(account.id, user.mt5.login);
            deployedHere = true;
            await account.waitConnected();
          } catch(deployErr) {
            console.log('[TP-WRAPPER] Deploy auto échoué pour ' + user._id + ': ' + deployErr.message);
            continue;
          }
        }

        const connection = account.getRPCConnection();
        await connection.connect();
        await connection.waitSynchronized();

        const positions = await connection.getPositions();
        if (!positions || !positions.length) {
          // Si on a deployé mais qu'il n'y a pas de positions, undeploy direct
          if (deployedHere) {
            try { await account.undeploy(); if (typeof trackUndeploy === 'function') trackUndeploy(account.id); } catch(e) {}
          }
          continue;
        }

        for (const pos of positions) {
          try {
            // ─── 1. CHARGER OU CRÉER LE TRACKING ─────────────────────
            let tracking = await positionsTrackingDb.findOneAsync({ positionId: pos.id });

            // Si tp3 déjà fait OU pas de runner → on skip (rien à gérer)
            if (tracking && tracking.tp3Done) continue;
            if (tracking && tracking.tp2Done && tracking.tp1Volume + tracking.tp2Volume >= parseFloat(pos.volume) * 0.99) continue;

            // ─── 2. RETROUVER L'ANALYSE ASSOCIÉE ─────────────────────
            const direction = pos.type === 'POSITION_TYPE_BUY' ? 'BUY' : 'SELL';
            const dateLimit = new Date(Date.now() - 24 * 60 * 60 * 1000);
            const analyses = await analysesDb.findAsync({
              userId: user._id,
              decision: direction,
              createdAt: { $gte: dateLimit }
            });

            let analyseMatch = null;
            for (const a of analyses) {
              // Bug fix : la DB stocke "entry" (pas "entree") — on supporte les deux
              const aEntree = parseFloat(a.entry || a.entree);
              // Tolérance 8$ (avant 5$) pour gérer le slippage et les LIMIT touchés à un prix légèrement différent
              if (!isNaN(aEntree) && Math.abs(aEntree - parseFloat(pos.openPrice)) < 8) {
                if (!analyseMatch || new Date(a.createdAt) > new Date(analyseMatch.createdAt)) {
                  analyseMatch = a;
                }
              }
            }
            // Note : la DB stocke aussi "tp" (pas "tp1") pour le TP1 — on supporte les deux
            if (!analyseMatch || (!analyseMatch.tp1 && !analyseMatch.tp)) continue;

            const tp1 = parseFloat(analyseMatch.tp1 || analyseMatch.tp);
            const tp2 = parseFloat(analyseMatch.tp2 || 0);
            const tp3 = parseFloat(analyseMatch.tp3 || 0);
            const score = parseFloat(analyseMatch.score || 7);

            // ─── DÉTECTION MODE DÉGRADÉ : client a posé UNIQUEMENT TP1 ? ─────
            // On compare le takeProfit MT5 actuel avec les TP de l'analyse :
            //   - Si pos.takeProfit ≈ tp1 → client a choisi TP1 SEULEMENT → mode dégradé
            //   - Si pos.takeProfit ≈ tp2 → client a choisi TP2 → mode 3-tier normal
            //   - Si pos.takeProfit ≈ tp3 → client a choisi TP3 → mode 3-tier normal
            const posTP = parseFloat(pos.takeProfit || 0);
            const tolMatch = 2; // tolérance 2$ pour XAU (gère slippage broker)
            const isModeDegrade = posTP > 0 && tp1 > 0 &&
              Math.abs(posTP - tp1) < tolMatch &&
              (!tp2 || Math.abs(posTP - tp2) > tolMatch) &&
              (!tp3 || Math.abs(posTP - tp3) > tolMatch);
            const entree = parseFloat(pos.openPrice);
            const prixActuel = parseFloat(pos.currentPrice);
            const isBuy = direction === 'BUY';
            const volumeActuel = parseFloat(pos.volume);

            // ─── 3. RÉCUPÉRER L'ATR POUR BUFFER DYNAMIQUE ────────────
            let atr = 5; // fallback XAU
            try {
              const candles = await connection.getHistoricalCandles(pos.symbol, '15m', undefined, 20) || [];
              if (candles.length >= 15) {
                let sum = 0;
                for (let i = candles.length - 14; i < candles.length; i++) {
                  const c = candles[i], p = candles[i-1];
                  sum += Math.max(c.high - c.low, Math.abs(c.high - p.close), Math.abs(c.low - p.close));
                }
                atr = sum / 14;
              }
            } catch(e) {}
            const buffer = getBufferBE(pos.symbol, atr);
            const distribution = getDistribution(score);

            // ─── 4. INITIALISER LE TRACKING SI NOUVEAU ───────────────
            if (!tracking) {
              tracking = {
                positionId: pos.id,
                symbol: pos.symbol,
                userId: user._id,
                volumeOriginal: volumeActuel,
                distribution,
                tp1Done: false, tp2Done: false, tp3Done: false,
                tp1Volume: 0, tp2Volume: 0, tp3Volume: 0,
                createdAt: new Date()
              };
              await positionsTrackingDb.insertAsync(tracking);
            }

            // ─── BUG FIX : utiliser volumeOriginal pour les calculs % ────
            // pos.volume diminue après chaque partiel, donc baser les % sur
            // pos.volume sous-estimerait les TP2/TP3. On utilise volumeOriginal
            // depuis le tracking (stocké à l'init).
            const volumeTotal = parseFloat(tracking.volumeOriginal || volumeActuel);

            // ═══════════════════════════════════════════════════════════
            // 🛡️ MODE DÉGRADÉ : client a choisi UNIQUEMENT TP1
            // ═══════════════════════════════════════════════════════════
            // Logique :
            //   1. À mi-chemin entre entrée et TP1 → fermer 50%
            //   2. Poser SL à BE + buffer
            //   3. Trailing structurel sur swings M5 jusqu'au TP1 final
            // Avantage : sécurise le trade même si client n'a pas configuré TP2/TP3
            if (isModeDegrade) {
              const distEntreeTP1 = Math.abs(tp1 - entree);
              const miChemin = isBuy ? entree + distEntreeTP1 * 0.5 : entree - distEntreeTP1 * 0.5;

              // ─── Étape 1 : à mi-chemin → ferme 50%, SL à BE+buffer ─────
              if (!tracking.tp1Done) {
                const miCheminAtteint = isBuy ? prixActuel >= miChemin : prixActuel <= miChemin;
                if (miCheminAtteint) {
                  const volPartiel = Math.round(volumeTotal * 0.5 * 100) / 100;
                  if (volPartiel >= 0.01) {
                    try {
                      await connection.closePositionPartially(pos.id, volPartiel);
                      console.log('[MODE-DEGRADE] Mi-chemin atteint sur ' + pos.symbol + ' : 50% ferme @ ' + prixActuel.toFixed(2));
                      await new Promise(r => setTimeout(r, 2000));

                      // SL à BE + buffer
                      const slBE = isBuy ? entree + buffer : entree - buffer;
                      try {
                        await connection.modifyPosition(pos.id, slBE, pos.takeProfit);
                        console.log('[MODE-DEGRADE] SL -> BE+' + buffer.toFixed(2) + '$ (= ' + slBE.toFixed(2) + ')');
                      } catch(err) { console.log('[MODE-DEGRADE] Erreur BE:', err.message); }

                      // Marquer le tracking comme "mi-chemin franchi" (réutilise tp1Done pour ne pas refermer)
                      await positionsTrackingDb.updateAsync(
                        { positionId: pos.id },
                        { $set: {
                          tp1Done: true,
                          modeDegrade: true,
                          miCheminTime: new Date(),
                          miCheminPrice: prixActuel,
                          miCheminVolume: volPartiel,
                          slMoved: slBE
                        } }
                      );

                      if (typeof creerNotification === 'function') {
                        try {
                          await creerNotification(user._id, 'tp_partiel',
                            '🛡️ Mi-chemin TP1 sur ' + pos.symbol + ' (mode degrade)',
                            '50% fermes a ' + prixActuel.toFixed(2) + ', SL -> BE+' + buffer.toFixed(2) + '$. Trailing active sur le reste jusqu\'a TP1.',
                            { miChemin: prixActuel, volumeFerme: volPartiel });
                        } catch(e) {}
                      }
                    } catch(err) { console.log('[MODE-DEGRADE] Erreur fermeture mi-chemin:', err.message); }
                  }
                }
                continue; // skip le mode 3-tier normal
              }

              // ─── Étape 2 : trailing structurel sur les 50% restants jusqu'a TP1 ─
              if (tracking.tp1Done && !tracking.tp3Done) {
                try {
                  const candlesM5 = await connection.getHistoricalCandles(pos.symbol, '5m', undefined, 30) || [];
                  const niveauTrailing = trouverNiveauTrailing(candlesM5, direction, 3);

                  if (niveauTrailing) {
                    const slActuel = parseFloat(pos.stopLoss);
                    const nouveauSL = isBuy ? niveauTrailing - buffer : niveauTrailing + buffer;
                    // Ne déplace que si ça avance dans le sens du trade
                    const ameliore = isBuy ? nouveauSL > slActuel : nouveauSL < slActuel;
                    if (ameliore) {
                      await connection.modifyPosition(pos.id, nouveauSL, pos.takeProfit);
                      console.log('[MODE-DEGRADE-TRAILING] SL -> ' + nouveauSL.toFixed(2) + ' (sous swing M5)');
                      await positionsTrackingDb.updateAsync(
                        { positionId: pos.id },
                        { $set: { lastTrailing: new Date(), slMoved: nouveauSL } }
                      );
                    }
                  }
                } catch(err) { console.log('[MODE-DEGRADE-TRAILING] Erreur:', err.message); }
                continue; // skip le mode 3-tier normal (pas de TP2/TP3 ici)
              }
            }

            // ═══ PALIER 1 : TP1 atteint ═══════════════════════════════
            if (!tracking.tp1Done) {
              const tp1Atteint = isBuy ? prixActuel >= tp1 : prixActuel <= tp1;
              if (tp1Atteint) {
                const volTP1 = Math.round(volumeTotal * distribution.tp1 * 100) / 100;
                if (volTP1 >= 0.01) {
                  try {
                    await connection.closePositionPartially(pos.id, volTP1);
                    console.log(`[TP1] Fermé ${volTP1}/${volumeTotal} sur ${pos.symbol} @ ${prixActuel} (mode ${distribution.mode})`);
                    await new Promise(r => setTimeout(r, 2000));

                    // SL → BE + buffer (dans le sens du trade)
                    const slBE = isBuy ? entree + buffer : entree - buffer;
                    try {
                      await connection.modifyPosition(pos.id, slBE, pos.takeProfit);
                      console.log(`[BE+] SL → ${slBE.toFixed(2)} (BE+${buffer.toFixed(2)}$)`);
                    } catch(err) { console.log('[BE+] Erreur:', err.message); }

                    await positionsTrackingDb.updateAsync(
                      { positionId: pos.id },
                      { $set: { tp1Done: true, tp1Time: new Date(), tp1Volume: volTP1, tp1Price: prixActuel, slMoved: slBE } }
                    );

                    if (typeof creerNotification === 'function') {
                      try {
                        await creerNotification(user._id, 'tp_partiel',
                          `🎯 TP1 atteint sur ${pos.symbol}`,
                          `${(distribution.tp1*100).toFixed(0)}% fermés à ${prixActuel.toFixed(2)}, SL → BE+${buffer.toFixed(2)}$. Reste ${(volumeTotal-volTP1).toFixed(2)} lots pour TP2/TP3.`,
                          { tp1: prixActuel, volumeFerme: volTP1 });
                      } catch(e) {}
                    }
                  } catch(err) { console.log('[TP1] Erreur fermeture:', err.message); continue; }
                }
              }
            }

            // ═══ PALIER 2 : TP2 atteint (si distribution prévoit TP2) ═
            else if (!tracking.tp2Done && distribution.tp2 > 0 && tp2 > 0) {
              const tp2Atteint = isBuy ? prixActuel >= tp2 : prixActuel <= tp2;
              if (tp2Atteint) {
                const volTP2 = Math.round(volumeTotal * distribution.tp2 * 100) / 100;
                if (volTP2 >= 0.01) {
                  try {
                    await connection.closePositionPartially(pos.id, volTP2);
                    console.log(`[TP2] Fermé ${volTP2} sur ${pos.symbol} @ ${prixActuel}`);
                    await new Promise(r => setTimeout(r, 2000));

                    // SL → lock TP1 (entrée + distance jusqu'à TP1, garantit profit)
                    const slLock = isBuy
                      ? entree + (tp1 - entree) * 0.5  // verrouille 50% du gain TP1
                      : entree - (entree - tp1) * 0.5;
                    try {
                      await connection.modifyPosition(pos.id, slLock, pos.takeProfit);
                      console.log(`[SL-LOCK] SL → ${slLock.toFixed(2)} (50% du gain TP1 verrouillé)`);
                    } catch(err) { console.log('[SL-LOCK] Erreur:', err.message); }

                    await positionsTrackingDb.updateAsync(
                      { positionId: pos.id },
                      { $set: { tp2Done: true, tp2Time: new Date(), tp2Volume: volTP2, tp2Price: prixActuel, slMoved: slLock } }
                    );

                    if (typeof creerNotification === 'function') {
                      try {
                        await creerNotification(user._id, 'tp_partiel',
                          `🎯 TP2 atteint sur ${pos.symbol}`,
                          `${(distribution.tp2*100).toFixed(0)}% fermés à ${prixActuel.toFixed(2)}. Trailing structurel activé sur le runner.`,
                          { tp2: prixActuel, volumeFerme: volTP2 });
                      } catch(e) {}
                    }
                  } catch(err) { console.log('[TP2] Erreur:', err.message); }
                }
              }
            }

            // ═══ PALIER 3 : RUNNER avec TRAILING STRUCTUREL ═══════════
            // Une fois TP2 fait, on suit les swings M5 pour faire monter le SL
            else if (tracking.tp2Done && !tracking.tp3Done && distribution.tp3 > 0) {
              try {
                const candlesM5 = await connection.getHistoricalCandles(pos.symbol, '5m', undefined, 30) || [];
                const niveauTrailing = trouverNiveauTrailing(candlesM5, direction, 3);

                if (niveauTrailing) {
                  const slActuel = parseFloat(pos.stopLoss);
                  const nouveauSL = isBuy ? niveauTrailing - buffer : niveauTrailing + buffer;
                  // Ne déplace que si ça avance dans le sens du trade
                  const ameliore = isBuy ? nouveauSL > slActuel : nouveauSL < slActuel;
                  if (ameliore) {
                    await connection.modifyPosition(pos.id, nouveauSL, pos.takeProfit);
                    console.log(`[TRAILING] SL → ${nouveauSL.toFixed(2)} (sous swing ${direction === 'BUY' ? 'low' : 'high'} M5)`);
                    await positionsTrackingDb.updateAsync(
                      { positionId: pos.id },
                      { $set: { lastTrailing: new Date(), slMoved: nouveauSL } }
                    );
                  }
                }

                // Si TP3 défini et atteint → fermer le runner
                if (tp3 > 0) {
                  const tp3Atteint = isBuy ? prixActuel >= tp3 : prixActuel <= tp3;
                  if (tp3Atteint) {
                    await connection.closePosition(pos.id);
                    console.log(`[TP3] Runner fermé sur ${pos.symbol} @ ${prixActuel}`);
                    await positionsTrackingDb.updateAsync(
                      { positionId: pos.id },
                      { $set: { tp3Done: true, tp3Time: new Date(), tp3Price: prixActuel } }
                    );
                  }
                }
              } catch(err) { console.log('[TRAILING] Erreur:', err.message); }
            }

          } catch(err) {
            if (!err.message.includes('not found')) console.log('[TP-3TIER] Erreur position:', err.message);
          }
        }

        // ─── FIX : Undeploy si on a deployé temporairement ──────────
        if (deployedHere && account) {
          try {
            await account.undeploy();
            if (typeof trackUndeploy === 'function') trackUndeploy(account.id);
          } catch(e) {}
        }
      } catch(err) {
        // Undeploy même en cas d'erreur pour pas garder un compte deployed inutilement
        if (deployedHere && account) {
          try { await account.undeploy(); if (typeof trackUndeploy === 'function') trackUndeploy(account.id); } catch(e) {}
        }
        if (!err.message.includes('not found')) console.log('[TP-3TIER] Erreur user:', err.message);
      }
    }
  } catch(err) { console.log('[TP-3TIER] Erreur globale:', err.message); }
}


// ═══════════════════════════════════════════════════════════════════
// 🧩 MODULE INLINÉ : PROMPT RULES STRICT/LAXISTE
// ═══════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════
// 🎯 prompt-rules.js — Section RÈGLES du prompt avec logique
//                      strict/laxiste explicitée
// ═══════════════════════════════════════════════════════════════════
// REMPLACE le bloc "📊 RÈGLES SIMPLES" du prompt (vers ligne 2080)
// Et ajoute les nouvelles instructions pour DOL, Premium/Discount, MSS
//
// À utiliser comme :
//   const promptRules = require('./prompt-rules');
//   const promptText = `...intro...${promptRules.getReglesText({ score, killZone, ...})}...JSON...`;
// ═══════════════════════════════════════════════════════════════════

function getReglesText({ killZoneName = 'OFF_HOURS', sessionActive = '', consecutiveLosses = 0 } = {}) {
  return `
═══════════════════════════════════════════════════════════════
📊 RÈGLES DE DÉCISION — STRICT vs LAXISTE
═══════════════════════════════════════════════════════════════

PHILOSOPHIE : Strict sur le CONTEXTE (non-négociable). Laxiste sur la
CONFLUENCE (relatif si pattern principal très propre).

═══════════════════════════════════════════════════════════════
🔒 FILTRES STRICTS — NE PAS TRADER si UN seul de ces points coche
═══════════════════════════════════════════════════════════════

1. **Tendance H1 ET M30 désalignées** avec ton signal
   → Pas de directional bias clair = casino. NE PAS TRADER.

2. **Prix en zone EQUILIBRIUM (45-55% du dealing range H1)**
   → Ni premium ni discount. ICT dit ATTENDRE que le prix sorte.
   → Exception : MSS très récent et net qui crée un nouveau range.

3. **Aucune liquidité claire à sweep** dans les 2× SL distance
   → Pas de Draw on Liquidity = pas de cible institutionnelle = pas de raison.

4. **Session asiatique sans cassure de range nette**
   → 70% des signaux asiat sont des faux. NE PAS TRADER sauf cassure
     CONFIRMÉE par bougie + clôture hors range.

5. **Vendredi après 18h Paris** ou **avant 8h lundi**
   → Liquidité fuyante, manipulation institutionnelle de fin/début de semaine.

6. **News rouge dans les 30 minutes** (NFP, FOMC, CPI, BCE)
   → Volatilité non-analysable, le setup peut être détruit en 1 bougie.

7. **${consecutiveLosses >= 2 ? 'TU AS DÉJÀ ' + consecutiveLosses + ' PERTES CONSÉCUTIVES AUJOURD\'HUI' : 'Si 2+ pertes consécutives dans la journée'}**
   → Réduction risque obligatoire (anti-tilt). Score minimum 8.5 pour continuer.

8. **Bougie M15 actuelle 3x+ ATR moyen ET pas de FVG créée**
   → Mouvement épuisé sans setup de continuation. NE PAS TRADER.
   → ATTENTION : si bougie violente AVEC FVG → c'est différent, voir règle laxiste 5.

═══════════════════════════════════════════════════════════════
🔓 RÈGLES LAXISTES — Accepter score 7-8 même sans tout cocher
═══════════════════════════════════════════════════════════════

1. **MSS clair sur M15 + retest de FVG en kill zone**
   → Pattern A+ mécanique d'ICT. Score peut être 8 sans toute la confluence.
   → SL = au-delà du sweep qui a précédé le MSS + buffer ATR×0.3.

2. **Silver Bullet (16h-17h Paris) + DOL identifié + structure alignée H1**
   → Window statistiquement très profitable (10h-11h NY).
   → Acceptable score 7 même si CRT non détecté.

3. **CRT Kasper STRICT confirmé sur M15** (pas SOFT)
   → Pattern auto-suffisant. Pas besoin de toute la confluence ICT.
   → Score 7-8 acceptable même en zone equilibrium si tendance H1 alignée.

4. **Sweep d'asian high/low + reversal en kill zone Londres ou NY**
   → Setup mécanique haute probabilité. Score 7 acceptable.
   → Le sweep DOIT être confirmé par clôture du côté opposé.

5. **Bougie violente AVEC création de FVG → ATTENDRE le retest de la FVG**
   → CONTRAIRE à ce que l'instinct dit : c'est UN DES MEILLEURS setups ICT.
   → C'est un Displacement → la FVG sera retestée 70%+ du temps.
   → Entrée : milieu de la FVG. SL : derrière la FVG. TP : extension du mouvement.

6. **Setup similaire à un setup gagnant historique** (cf. 🏆 dans le prompt)
   → Si pattern ressemble à un trade gagnant passé du même user en même session
   → Boost confiance, score peut monter de +1.

═══════════════════════════════════════════════════════════════
🎯 SCORING ADDITIF (transparence totale)
═══════════════════════════════════════════════════════════════

Calcule le score en additionnant ces points (max théorique ~14, on cap à 10) :

CONTEXTE (obligatoire pour score > 6) :
+ 2 pts : Cible DOL (Draw on Liquidity) clairement identifiée
+ 2 pts : Prix en zone Premium ou Discount alignée avec le signal
+ 2 pts : MSS ou BOS récent aligné avec direction du trade
+ 1 pt  : Tendance H1 alignée

PATTERN PRINCIPAL :
+ 2 pts : CRT Kasper STRICT confirmé sur M15
+ 1.5 pt: OB de haute qualité (avec displacement, non mitigé)
+ 1 pt  : FVG en confluence avec entrée
+ 1.5 pt: Sweep de liquidité récent dans le sens du retournement

CONTEXTE TEMPOREL :
+ 2 pts : Silver Bullet (16h-17h Paris)
+ 1 pt  : London Open ou NY AM kill zone
- 1 pt  : Hors kill zone (OFF_HOURS)
- 2 pts : Session asiatique sans cassure de range

ÉTAT DE COMPTE :
+ 0.5 pt: Pas de news rouge dans 30 min
${consecutiveLosses >= 2 ? `- 1 pt  : ${consecutiveLosses} pertes consécutives aujourd'hui (en cours)` : '- 1 pt  : Si 2+ pertes consécutives'}

DÉCISION FINALE :
- Score ≥ 7 → TRADE (avec distribution selon score, voir TP/SL ci-dessous)
- Score 5-6.9 → BORDERLINE (NE PAS TRADER en règle générale, sauf règles laxistes 1, 2, 3 ou 5)
- Score < 5 → NE PAS TRADER

═══════════════════════════════════════════════════════════════
💼 TP/SL — DISTRIBUTION SELON SCORE
═══════════════════════════════════════════════════════════════

Le bot fermera automatiquement la position en plusieurs paliers selon le score.
TU DOIS TOUJOURS DONNER TP1, TP2, TP3 dans la réponse JSON.

SL :
- Position structurelle : derrière sweep, OB, ou swing significatif
- Buffer dynamique : ATR(14) M15 × 0.3 (jamais < 3$ sur XAU)
- Le bot ajoutera AUTOMATIQUEMENT BE+buffer après TP1, donc tu peux poser un SL serré.

TP1 (premier palier — sécurise une partie) :
- R:R 1:1.5 minimum (1:1 acceptable si setup B en zone défensive)
- Niveau atteignable : prochain mini-objectif (FVG opposée, swing intermédiaire)

TP2 (palier intermédiaire) :
- R:R 1:2.5 idéal
- Niveau structurel : equal highs/lows, asian range opposé, OB H1 plus loin

TP3 (runner — extension) :
- R:R 1:4 ou plus
- Niveau MAJEUR : sweep d'un old high/low H1, daily high/low, niveau psychologique

DISTRIBUTION (le bot s'en charge automatiquement) :
- Score ≥ 9 (A+) : 40% TP1, 30% TP2, 30% runner avec trailing
- Score 7-8 (A)  : 50% TP1, 30% TP2, 20% runner avec trailing
- Score 6   (B)  : 70% TP1, 30% TP2, pas de runner (gestion défensive)

═══════════════════════════════════════════════════════════════
⛔ RÈGLES ABSOLUES (override tout le reste)
═══════════════════════════════════════════════════════════════

- Si tendance H1 ET M30 contre ton signal → NE PAS TRADER, peu importe le reste
- Si une leçon précédente dit "ne pas faire X" et le setup actuel = X → respecte-la
- Si Silver Bullet active mais aucun DOL → NE PAS TRADER (timing seul ne suffit pas)
- Si tu hésites entre BUY et SELL → NE PAS TRADER (l'incertitude = perte)
- Si tu n'arrives pas à expliquer en 1 phrase POURQUOI ce trade va marcher → NE PAS TRADER

CONTEXTE ACTUEL : ${sessionActive}
KILL ZONE : ${killZoneName}
${consecutiveLosses >= 2 ? `⚠️ ALERTE : ${consecutiveLosses} pertes consécutives aujourd'hui — sois EXTRÊMEMENT sélectif` : ''}
═══════════════════════════════════════════════════════════════
`;
}

// ─── Export ─────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════
// 🔗 OBJETS DE COMPATIBILITÉ (pour ne pas avoir à changer le code appelant)
// ═══════════════════════════════════════════════════════════════════
const ict = {
  detecterSwings, calculerATR, getDealingRange, detecterStructure,
  detecterLiquidite, getAsianRange, getDrawOnLiquidity, detecterSweepRécent,
  validerOB, getKillZone, scoreSetup, analyseComplete, formatPourPrompt
};
const promptRules = { getReglesText };


// ═══════════════════════════════════════════════════════════════════
// 🚀 FETCH UNIFIÉ — économise 60-70% des appels MetaApi
// ═══════════════════════════════════════════════════════════════════
// Avant : chaque fonction (OBFVG, Indicateurs, Protections) faisait son propre
// deploy + sa propre récupération de bougies. Résultat : 8-12 appels par /analyze.
//
// Maintenant : un seul deploy, récupération PARALLÈLE de tous les TF, cache 90s
// pour que les fonctions appelées dans la foulée réutilisent les données.
//
// Cache key : userId + symbole (un cache par utilisateur+instrument)
// TTL : 90s (suffit pour qu'une /analyze complète réutilise sans risque de staleness)

const _marketDataCache = new Map(); // key → { data, time }
const MARKET_CACHE_TTL_MS = 90 * 1000;

async function fetchAllMarketData(userId, symbole) {
  if (!metaApi) return null;
  const cacheKey = userId + ':' + (symbole || 'XAUUSD').toUpperCase();

  // ─── Cache hit ? ──────────────────────────────────────────────
  const cached = _marketDataCache.get(cacheKey);
  if (cached && (Date.now() - cached.time) < MARKET_CACHE_TTL_MS) {
    return cached.data;
  }

  try {
    const user = await db.findOneAsync({ _id: userId });
    if (!user || !user.mt5 || !user.mt5.metaApiAccountId) return null;

    const account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
    // On suppose que le deploy est géré en amont par /analyze.
    // Si pas DEPLOYED, on retourne null et chaque fonction tombera silencieusement.
    if (account.state !== 'DEPLOYED') return null;

    const connection = account.getRPCConnection();
    await connection.connect();
    await connection.waitSynchronized();

    // ─── Résolution du symbole avec suffixes ─────────────────────
    const sym = (symbole || 'XAUUSD').toUpperCase();
    const suffixes = ['', '-VIP', '-STD', '-ECN', '-PRO', '-Raw', '.a', '_m', '-micro'];
    let symbolResolu = null;
    let testCandles = [];
    for (const sfx of suffixes) {
      try {
        const symFull = sym + sfx;
        testCandles = await connection.getHistoricalCandles(symFull, '15m', undefined, 5) || [];
        if (testCandles.length) {
          symbolResolu = symFull;
          break;
        }
      } catch(e) {}
    }
    if (!symbolResolu) return null;

    // ─── Récupération PARALLÈLE de tous les TF (1 seul deploy, 5 appels en parallèle) ─
    const [candlesH1, candlesM30, candlesM15, candlesM5, tickInfo] = await Promise.all([
      connection.getHistoricalCandles(symbolResolu, '1h', undefined, 60).catch(() => []),
      connection.getHistoricalCandles(symbolResolu, '30m', undefined, 60).catch(() => []),
      connection.getHistoricalCandles(symbolResolu, '15m', undefined, 60).catch(() => []),
      connection.getHistoricalCandles(symbolResolu, '5m', undefined, 60).catch(() => []),
      connection.getSymbolPrice(symbolResolu).catch(() => null)
    ]);

    let prixActuel = null;
    if (tickInfo && tickInfo.bid) prixActuel = (tickInfo.bid + tickInfo.ask) / 2;

    const data = {
      symbolResolu,
      candlesH1,
      candlesM30,
      candlesM15,
      candlesM5,
      prixActuel,
      time: Date.now()
    };

    // Stocker en cache
    _marketDataCache.set(cacheKey, { data, time: Date.now() });

    // Cleanup automatique : virer les entrées plus vieilles que 5 min
    if (_marketDataCache.size > 50) {
      const now = Date.now();
      for (const [k, v] of _marketDataCache.entries()) {
        if (now - v.time > 5 * 60 * 1000) _marketDataCache.delete(k);
      }
    }

    return data;
  } catch(err) {
    console.log('[FETCH-MARKET-DATA] Erreur:', err.message);
    return null;
  }
}

// Helper pour invalider le cache d'un user (utile quand il fait une nouvelle analyse)
function invaliderCacheMarket(userId, symbole) {
  if (!userId) return;
  if (symbole) {
    _marketDataCache.delete(userId + ':' + symbole.toUpperCase());
  } else {
    // Invalider toutes les entrées du user
    for (const k of _marketDataCache.keys()) {
      if (k.startsWith(userId + ':')) _marketDataCache.delete(k);
    }
  }
}

async function getBlocIndicateursTechniques(userId, symbole) {
  if (!metaApi) return '';
  try {
    // ─── OPTIMISATION : utiliser le cache unifié ──────────────────
    // Si appelée pendant une /analyze, les bougies sont déjà en cache,
    // pas de nouvel appel MetaApi
    const marketData = await fetchAllMarketData(userId, symbole);
    if (!marketData) return '';

    const candlesH1 = marketData.candlesH1;
    const candlesM15 = marketData.candlesM15;
    const candlesM5 = marketData.candlesM5;
    const prixActuel = marketData.prixActuel;

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
    // ─── OPTIMISATION : utiliser le cache unifié ──────────────────
    const symbole = (parsed.instrument || 'XAUUSD').toUpperCase();
    const marketData = await fetchAllMarketData(userId, symbole);
    if (!marketData) return parsed;

    const candlesM15 = marketData.candlesM15;
    const prixActuel = marketData.prixActuel;
    const symbolResolu = marketData.symbolResolu;

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

    // ─── PROTECTION 5 : ANTI-CONTRE-TENDANCE ROBUSTE (5 méthodes + vote) ─
    // 5 méthodes indépendantes par TF (H1 et M30) + vote majoritaire 3+/5.
    // OPTIMISATION : utilise le cache marketData (pas de nouvel appel MetaApi)
    try {
      const candlesH1 = marketData.candlesH1 || [];
      const candlesM30 = marketData.candlesM30 || [];

      if (candlesH1.length >= 50 && candlesM30.length >= 50) {
        const tH1 = detecterTendanceRobuste(candlesH1);
        const tM30 = detecterTendanceRobuste(candlesM30);
        console.log(`[TENDANCE] H1=${tH1.trend} (${tH1.confidence}/5) M30=${tM30.trend} (${tM30.confidence}/5)`);

        // MSS récent sur M15 = override possible (vrai retournement)
        const structM15 = detecterStructure(candlesM15, 3);
        const mssRecent = structM15.event && (structM15.event.type === 'MSS_BULLISH' || structM15.event.type === 'MSS_BEARISH');
        const mssAlignedAvecSignal = mssRecent && (
          (isBuy && structM15.event.type === 'MSS_BULLISH') ||
          (!isBuy && structM15.event.type === 'MSS_BEARISH')
        );

        const signalContreH1 = (isBuy && tH1.trend === 'BEARISH') || (!isBuy && tH1.trend === 'BULLISH');
        const signalContreM30 = (isBuy && tM30.trend === 'BEARISH') || (!isBuy && tM30.trend === 'BULLISH');

        // Stocker pour le client/frontend
        parsed.tendanceServerH1 = tH1.trend;
        parsed.tendanceServerM30 = tM30.trend;
        parsed.tendanceConfidenceH1 = tH1.confidence;
        parsed.tendanceConfidenceM30 = tM30.confidence;

        // Cas 1 : H1 ET M30 contre → ANNULATION (sauf MSS aligné)
        if (signalContreH1 && signalContreM30) {
          if (mssAlignedAvecSignal) {
            scoreReduit = true;
            alertes.push(`H1+M30 contre ${parsed.decision} (${tH1.trend}/${tM30.trend}) MAIS MSS ${structM15.event.type} aligné M15 → score réduit`);
          } else {
            tradeAnnule = true;
            alertes.push(`🚫 CONTRE-TENDANCE ROBUSTE : H1=${tH1.trend} (${tH1.confidence}/5) + M30=${tM30.trend} (${tM30.confidence}/5) vs ${parsed.decision} → annulé`);
          }
        }
        // Cas 2 : un seul TF contre avec confidence forte (4+/5) → annulé
        else if ((signalContreH1 && tH1.confidence >= 4) || (signalContreM30 && tM30.confidence >= 4)) {
          if (!mssAlignedAvecSignal) {
            tradeAnnule = true;
            const tf = signalContreH1 ? 'H1' : 'M30';
            const conf = signalContreH1 ? tH1.confidence : tM30.confidence;
            const tt = signalContreH1 ? tH1.trend : tM30.trend;
            alertes.push(`🚫 ${tf}=${tt} confidence forte ${conf}/5 vs ${parsed.decision} → annulé`);
          } else {
            scoreReduit = true;
            alertes.push(`Tendance forte contre mais MSS aligné → score réduit`);
          }
        }
        // Cas 3 : un seul TF contre, confidence modérée (3/5) → score réduit
        else if (signalContreH1 || signalContreM30) {
          scoreReduit = true;
          const tf = signalContreH1 ? 'H1' : 'M30';
          alertes.push(`Tendance ${tf} contre signal ${parsed.decision} (${signalContreH1 ? tH1.confidence : tM30.confidence}/5) → score réduit`);
        }
      } else {
        console.log('[PROTECTION-CT] Pas assez de bougies (H1=' + candlesH1.length + ', M30=' + candlesM30.length + ')');
      }
    } catch(err) {
      console.log('[PROTECTION-CT] Erreur:', err.message);
    }

    // ─── PROTECTION 6 : RSI M30/H1 EN FORTE TENDANCE ──────────────
    // Le RSI à 39 sur M30 en plein downtrend = signal très bearish, pas un
    // simple "score réduit". Si RSI M30 < 40 ET signal BUY → annulé.
    // Symétrique pour SELL avec RSI > 60.
    try {
      // OPTIMISATION : utilise le cache marketData
      const candlesM30 = marketData.candlesM30 || [];
      if (candlesM30.length >= 15) {
        const rsiM30 = calculerRSI(candlesM30, 14);
        if (rsiM30 !== null) {
          // Seuils en 2 paliers :
          //   - Très fort (< 30 / > 70) → ANNULÉ (momentum extrême)
          //   - Modéré (30-40 / 60-70) → score réduit (momentum présent mais pas extrême)
          if (isBuy && rsiM30 < 30) {
            tradeAnnule = true;
            alertes.push(`🚫 RSI M30 ${rsiM30.toFixed(1)} < 30 → survente extrême ET tu veux BUY → momentum baissier dur, BUY annulé`);
          } else if (!isBuy && rsiM30 > 70) {
            tradeAnnule = true;
            alertes.push(`🚫 RSI M30 ${rsiM30.toFixed(1)} > 70 → surachat extrême ET tu veux SELL → momentum haussier dur, SELL annulé`);
          } else if (isBuy && rsiM30 < 40) {
            scoreReduit = true;
            alertes.push(`RSI M30 ${rsiM30.toFixed(1)} < 40 → momentum baissier modéré, score réduit`);
          } else if (!isBuy && rsiM30 > 60) {
            scoreReduit = true;
            alertes.push(`RSI M30 ${rsiM30.toFixed(1)} > 60 → momentum haussier modéré, score réduit`);
          }
        }
      }
    } catch(err) {
      console.log('[PROTECTION-RSI-M30] Erreur:', err.message);
    }

    // ─── PROTECTION 7 : COHÉRENCE PREMIUM/DISCOUNT vs SENS ─────────
    // Si l'IA a retourné premiumDiscount = PREMIUM mais propose BUY sans MSS_BULLISH,
    // c'est une violation directe d'ICT → annulation hard.
    if (parsed.premiumDiscount && parsed.structureEvent !== undefined) {
      const pd = String(parsed.premiumDiscount).toUpperCase();
      const ev = String(parsed.structureEvent || 'NONE').toUpperCase();
      const aMssBullish = ev === 'MSS_BULLISH';
      const aMssBearish = ev === 'MSS_BEARISH';
      if (isBuy && pd === 'PREMIUM' && !aMssBullish) {
        tradeAnnule = true;
        alertes.push(`🚫 BUY en zone PREMIUM sans MSS_BULLISH récent → violation ICT, annulé`);
      } else if (!isBuy && pd === 'DISCOUNT' && !aMssBearish) {
        tradeAnnule = true;
        alertes.push(`🚫 SELL en zone DISCOUNT sans MSS_BEARISH récent → violation ICT, annulé`);
      }
    }

    // ─── PROTECTION 8 : COHÉRENCE ENTRÉE / SL ──────────────────────
    // Pour BUY : SL doit être STRICTEMENT < entrée
    // Pour SELL : SL doit être STRICTEMENT > entrée
    // Sinon on a un trade malformé qui sera silencieusement inversé par le calcul dist
    if (entree > 0 && sl > 0) {
      if (isBuy && sl >= entree) {
        tradeAnnule = true;
        alertes.push(`🚫 BUY avec SL (${sl}) >= entrée (${entree}) → trade malformé, annulé`);
      } else if (!isBuy && sl <= entree) {
        tradeAnnule = true;
        alertes.push(`🚫 SELL avec SL (${sl}) <= entrée (${entree}) → trade malformé, annulé`);
      }
    }

    // ─── PROTECTION 8b : R:R MINIMUM CÔTÉ SERVEUR ───────────────────
    // Vérifie que le TP1 offre au moins un R:R de 1.2 par rapport au SL.
    // L'IA peut proposer des setups mal calibrés (TP trop proche du SL).
    // On ne laisse pas passer un trade avec un RR < 1.2 sur le TP1.
    // RR calculé sur l'entrée (pas le prix actuel — déjà vérifié en protection 3).
    if (entree > 0 && sl > 0 && tp > 0) {
      const distSLEntree = Math.abs(entree - sl);
      const distTPEntree = Math.abs(tp - entree);
      const rrEntree = distSLEntree > 0 ? distTPEntree / distSLEntree : 0;
      if (rrEntree < 1.2) {
        tradeAnnule = true;
        alertes.push(`🚫 R:R insuffisant : TP1 à ${distTPEntree.toFixed(1)}$ vs SL à ${distSLEntree.toFixed(1)}$ → R:R ${rrEntree.toFixed(2)} < 1.2 minimum requis, trade annulé`);
      } else if (rrEntree < 1.5) {
        scoreReduit = true;
        alertes.push(`R:R TP1 ${rrEntree.toFixed(2)} faible (< 1.5 idéal) → score réduit`);
      }
    }

    // ─── PROTECTION 8c : NEWS ÉCONOMIQUES MAJEURES ──────────────────
    // Bloque tout trade dans une fenêtre de ±30 min autour des news rouges
    // majeures : NFP (1er vendredi du mois 14h30 UTC), FOMC (env. 20h UTC),
    // CPI US (mercredi ~14h30 UTC), BCE (~13h45 UTC le jeudi de décision).
    // On ne peut pas requêter un calendrier économique externe (pas de réseau),
    // donc on bloque les CRÉNEAUX horaires statistiquement dangereux.
    // L'utilisateur peut toujours trader hors de ces fenêtres.
    try {
      const now = new Date();
      const dayUTC = now.getUTCDay();   // 0=dim, 1=lun ... 5=ven, 6=sam
      const hourUTC = now.getUTCHours();
      const minUTC = now.getUTCMinutes();
      const totalMinUTC = hourUTC * 60 + minUTC;

      // Fenêtre de blocage = ±30 min autour de l'événement
      const WINDOW = 30; // minutes
      const dansLaFenetre = (cibleH, cibleM) => {
        const cibleTotal = cibleH * 60 + cibleM;
        return Math.abs(totalMinUTC - cibleTotal) <= WINDOW;
      };

      const newsAlerte = [];

      // NFP : 1er vendredi du mois à 14h30 UTC
      // Heuristique : vendredi + jour <= 7 → c'est le 1er vendredi
      if (dayUTC === 5 && now.getUTCDate() <= 7 && dansLaFenetre(14, 30)) {
        newsAlerte.push('NFP (1er vendredi du mois, 14h30 UTC)');
      }

      // CPI US : mercredi à 14h30 UTC (toujours publiés le mercredi)
      // Pas tous les mercredis mais assez fréquent pour bloquer par défaut
      if (dayUTC === 3 && dansLaFenetre(14, 30)) {
        newsAlerte.push('CPI US possible (mercredi 14h30 UTC)');
      }

      // FOMC : décisions ~20h00 UTC (mercredi, environ 8×/an)
      // Même logique : mercredi soir = créneau FOMC potentiel
      if (dayUTC === 3 && dansLaFenetre(20, 0)) {
        newsAlerte.push('FOMC possible (mercredi 20h00 UTC)');
      }

      // BCE : décisions ~13h45 UTC, conférences ~14h30 UTC (jeudi ~8×/an)
      if (dayUTC === 4 && (dansLaFenetre(13, 45) || dansLaFenetre(14, 30))) {
        newsAlerte.push('BCE possible (jeudi 13h45/14h30 UTC)');
      }

      if (newsAlerte.length > 0) {
        tradeAnnule = true;
        alertes.push(`🚫 FENÊTRE NEWS ROUGE : ${newsAlerte.join(', ')} — trading suspendu ±30 min autour de la publication (volatilité non analysable)`);
      }
    } catch(newsErr) {
      console.log('[PROTECTION-NEWS] Erreur:', newsErr.message);
    }

    // ─── PROTECTION 9 : RSI EXTRÊME M15 (HARD BLOCK, pas juste textuel) ─
    // Override serveur dur si RSI dans zone extrême opposée au sens
    if (rsi !== null) {
      if (isBuy && rsi >= 78) {
        tradeAnnule = true;
        alertes.push(`🚫 BUY avec RSI M15 ${rsi} >= 78 (surachat extrême) → annulé hard`);
      } else if (!isBuy && rsi <= 22) {
        tradeAnnule = true;
        alertes.push(`🚫 SELL avec RSI M15 ${rsi} <= 22 (survente extrême) → annulé hard`);
      }
    }

    // ─── APPLICATION ──────────────────────────────────────────────
    // FIX problème 7 : ASSERTION DÉFENSIVE
    // verifierProtectionsAvancees ne doit JAMAIS inverser BUY ↔ SELL.
    // Elle peut seulement annuler (NE PAS TRADER) ou réduire le score.
    const decisionInitiale = parsed.decision;
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
    // Sécurité : si la décision finale n'est ni 'NE PAS TRADER' ni la décision initiale,
    // c'est un bug → on force NE PAS TRADER pour rester sûr
    if (parsed.decision !== 'NE PAS TRADER' && parsed.decision !== decisionInitiale) {
      console.log('[PROTECTIONS-BUG] Décision modifiée de ' + decisionInitiale + ' vers ' + parsed.decision + ' → forçage NE PAS TRADER');
      parsed.decision = 'NE PAS TRADER';
      parsed.score = 0;
      parsed.protectionsAlertes = (parsed.protectionsAlertes || '') + ' | BUG SÉCURITÉ : décision inversée détectée';
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
    // ─── ÉCONOMIE : utiliser le cache si dispo (zero deploy) ───────
    if (typeof fetchAllMarketData === 'function') {
      const cached = await fetchAllMarketData(userId, symbole);
      if (cached && cached.prixActuel) {
        return cached.prixActuel;
      }
    }

    // Fallback : pas de cache, on doit deploy temporairement
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
    // ─── OPTIMISATION : utiliser le cache unifié ──────────────────
    const marketData = await fetchAllMarketData(userId, symbole);
    if (!marketData) return '';

    const candlesM15 = marketData.candlesM15;
    const candlesM5 = marketData.candlesM5;
    const candlesH1 = marketData.candlesH1;

    if (!candlesM15.length && !candlesM5.length) return '';

    // ─── ANALYSE ICT COMPLÈTE (DOL, P/D, MSS, kill zone, ATR) ─────
    const analyseICT = await ict.analyseComplete(candlesM15, candlesH1, candlesM5);

    // ─── OB/FVG existant + validation qualité ─────────────────────
    const obM15 = detecterOrderBlocks(candlesM15);
    const fvgM15 = detecterFairValueGaps(candlesM15);
    const obM5 = detecterOrderBlocks(candlesM5);
    const fvgM5 = detecterFairValueGaps(candlesM5);
    const obM15Bull = obM15.bullish.map(o => ict.validerOB(o, candlesM15));
    const obM15Bear = obM15.bearish.map(o => ict.validerOB(o, candlesM15));

    // ─── Construction du bloc texte enrichi ───────────────────────
    let txt = ict.formatPourPrompt(analyseICT);

    txt += '\n📦 ORDER BLOCKS & FAIR VALUE GAPS :\n';
    if (obM15Bull.length) {
      txt += 'OB BULLISH M15 :\n';
      obM15Bull.forEach(o => {
        txt += `  - ${o.zone.low.toFixed(2)} - ${o.zone.high.toFixed(2)} [qualité: ${o.qualite}${o.mitigated ? ', déjà mitigé' : ''}]\n`;
      });
    }
    if (obM15Bear.length) {
      txt += 'OB BEARISH M15 :\n';
      obM15Bear.forEach(o => {
        txt += `  - ${o.zone.low.toFixed(2)} - ${o.zone.high.toFixed(2)} [qualité: ${o.qualite}${o.mitigated ? ', déjà mitigé' : ''}]\n`;
      });
    }
    if (fvgM15.bullish.length) {
      txt += 'FVG BULLISH M15 :\n';
      fvgM15.bullish.forEach(f => txt += `  - ${f.zone.low.toFixed(2)} - ${f.zone.high.toFixed(2)} (taille ${f.size.toFixed(2)}$)\n`);
    }
    if (fvgM15.bearish.length) {
      txt += 'FVG BEARISH M15 :\n';
      fvgM15.bearish.forEach(f => txt += `  - ${f.zone.low.toFixed(2)} - ${f.zone.high.toFixed(2)} (taille ${f.size.toFixed(2)}$)\n`);
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

    txt += '\nUTILISE CES NIVEAUX EN PRIORITÉ. Privilégie les OB qualité HIGH non mitigés.\n';
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
// 📧 ALERTE EMAIL SETUP A+ (score ≥ 8) — broadcast à tous les clients
// ═══════════════════════════════════════════════════════════════════
// Déclenché automatiquement après chaque analyse dont le score ≥ 8
// Envoie un email à tous les clients abonnés (subscribed=true + non bannis)
// avec le setup complet : direction, instrument, entrée, SL, TP1/2/3, score, raison IA.
// Envoi en parallèle via Promise.allSettled (1 échec ne bloque pas les autres).

async function envoyerAlerteSetupAPlus(parsed, analyseId) {
  // Sécurités : on n'envoie que si score ≥ 8 et décision BUY ou SELL
  const score = parseFloat(parsed.score) || 0;
  if (score < 8) return;
  if (parsed.decision !== 'BUY' && parsed.decision !== 'SELL') return;

  try {
    // Récupérer tous les clients abonnés, vérifiés, non bannis
    const clients = await db.findAsync({
      role: { $ne: 'admin' },
      subscribed: true,
      isVerified: true,
      banned: { $ne: true }
    });

    if (!clients || clients.length === 0) {
      console.log('[ALERTE-EMAIL] Aucun client abonné à notifier');
      return;
    }

    // ─── Construction des données du setup ───────────────────────
    const isBuy   = parsed.decision === 'BUY';
    const couleur  = isBuy ? '#00ff88' : '#ff3060';
    const emoji    = isBuy ? '🟢' : '🔴';
    const scoreEmoji = score >= 9 ? '🏆' : '⭐';
    const urgence  = score >= 9.5 ? '🔴 ULTRA URGENT' : score >= 9 ? '🟠 URGENT' : '🟡 SETUP A+';

    const instrument = parsed.instrument || 'XAUUSD';
    const entree     = parsed.entree     || '—';
    const sl         = parsed.sl         || '—';
    const tp1        = parsed.tp1        || '—';
    const tp2        = parsed.tp2        || '—';
    const tp3        = parsed.tp3        || '—';
    const lots       = parsed.lots       || '—';
    const raison     = parsed.raisonCourte || parsed.raison || parsed.analyse || 'Setup validé par l\'IA';

    // Lien vers l'app (le client clique et arrive directement sur son dashboard)
    const lienApp = BASE_URL;

    // ─── Template HTML email ──────────────────────────────────────
    // ✅ FIX SPAM : template fond BLANC (fond noir = signal phishing pour Gmail/Outlook)
    // Les filtres anti-spam scorent très mal les emails dark-mode non standards
    const htmlEmail = `
<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
  <div style="max-width:560px;margin:0 auto;padding:24px 16px;">

    <!-- HEADER -->
    <div style="background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);margin-bottom:0;">

      <!-- Barre de couleur selon direction -->
      <div style="background:${isBuy ? '#16a34a' : '#dc2626'};padding:20px 24px;text-align:center;">
        <div style="font-size:11px;letter-spacing:3px;color:rgba(255,255,255,0.7);text-transform:uppercase;margin-bottom:6px;">J4keIA — Signal de trading</div>
        <div style="font-size:28px;font-weight:900;color:#ffffff;margin-bottom:4px;">${isBuy ? '▲' : '▼'} ${parsed.decision} ${instrument}</div>
        <div style="display:inline-block;background:rgba(255,255,255,0.2);padding:4px 14px;border-radius:20px;font-size:12px;color:#fff;font-weight:600;">Score IA : ${scoreEmoji} ${score}/10</div>
      </div>

      <!-- NIVEAUX DU TRADE -->
      <div style="padding:20px 24px;background:#ffffff;">
        <div style="font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">Niveaux du trade</div>
        <table style="width:100%;border-collapse:collapse;">
          <tr style="border-bottom:1px solid #f3f4f6;">
            <td style="padding:10px 0;color:#374151;font-size:13px;font-weight:600;">Entrée</td>
            <td style="padding:10px 0;color:#111827;font-size:16px;font-weight:700;text-align:right;">${entree}</td>
          </tr>
          <tr style="border-bottom:1px solid #f3f4f6;">
            <td style="padding:10px 0;color:#374151;font-size:13px;font-weight:600;">Stop Loss</td>
            <td style="padding:10px 0;color:#dc2626;font-size:16px;font-weight:700;text-align:right;">${sl}</td>
          </tr>
          <tr style="border-bottom:1px solid #f3f4f6;">
            <td style="padding:10px 0;color:#374151;font-size:13px;font-weight:600;">TP1</td>
            <td style="padding:10px 0;color:#16a34a;font-size:16px;font-weight:700;text-align:right;">${tp1}</td>
          </tr>
          <tr style="border-bottom:1px solid #f3f4f6;">
            <td style="padding:10px 0;color:#374151;font-size:13px;font-weight:600;">TP2</td>
            <td style="padding:10px 0;color:#16a34a;font-size:14px;font-weight:700;text-align:right;">${tp2}</td>
          </tr>
          <tr style="border-bottom:1px solid #f3f4f6;">
            <td style="padding:10px 0;color:#374151;font-size:13px;font-weight:600;">TP3</td>
            <td style="padding:10px 0;color:#16a34a;font-size:14px;font-weight:700;text-align:right;">${tp3}</td>
          </tr>
          ${lots !== '—' ? `<tr>
            <td style="padding:10px 0;color:#374151;font-size:13px;font-weight:600;">Lots suggérés</td>
            <td style="padding:10px 0;color:#d97706;font-size:14px;font-weight:700;text-align:right;">${lots}</td>
          </tr>` : ''}
        </table>
      </div>

      <!-- ANALYSE IA -->
      <div style="padding:16px 24px;background:#f9fafb;border-top:1px solid #e5e7eb;">
        <div style="font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Analyse IA</div>
        <div style="font-size:13px;color:#374151;line-height:1.6;">${raison}</div>
      </div>

      <!-- BOUTON CTA -->
      <div style="padding:20px 24px;text-align:center;background:#ffffff;border-top:1px solid #e5e7eb;">
        <a href="${lienApp}" style="display:inline-block;background:${isBuy ? '#16a34a' : '#dc2626'};color:#ffffff;padding:14px 36px;text-decoration:none;font-weight:700;font-size:14px;border-radius:6px;">
          Voir le setup complet
        </a>
      </div>

      <!-- FOOTER -->
      <div style="padding:14px 24px;text-align:center;background:#f9fafb;border-top:1px solid #e5e7eb;">
        <p style="font-size:11px;color:#9ca3af;line-height:1.5;margin:0;">
          Ce signal est fourni à titre informatif. Le trading comporte des risques.<br>
          J4keIA — Ref #${analyseId ? analyseId.substring(0, 8) : '—'} &nbsp;|&nbsp;
          <a href="mailto:${process.env.BREVO_SENDER}?subject=unsubscribe" style="color:#9ca3af;">Se désabonner</a>
        </p>
      </div>
    </div>

  </div>
</body>
</html>`;

    // ─── Envoi en parallèle à tous les clients ────────────────────
    console.log('[ALERTE-EMAIL] Envoi setup A+ (score ' + score + ') à ' + clients.length + ' client(s)...');

    // ─── NOTIF IN-APP : remplit la cloche pour ceux dans l'app ────
    // En plus de l'email, on créé une notif dans la DB pour que la cloche
    // s'allume si le client est déjà connecté à l'app
    for (const client of clients) {
      try {
        // Recalculer le lot pour CE client (capital perso, pas celui du shareur)
        let lotsClient = parsed.lots; // fallback
        let montantClient = parsed.montantRisque;
        if (client.mt5 && client.mt5.capital && parsed.slPips) {
          const capitalC = parseFloat(client.mt5.capital);
          const risquePctC = score >= 8 ? 3 : score >= 6 ? 2 : 1;
          const slDistC = parsed.entree && parsed.sl ? Math.abs(parseFloat(parsed.entree) - parseFloat(parsed.sl)) : null;
          const lotsCalc = calculerLots(capitalC, risquePctC, parsed.slPips, parsed.instrument || '', slDistC);
          if (lotsCalc) {
            lotsClient = lotsCalc;
            montantClient = (capitalC * risquePctC / 100).toFixed(2);
          }
        }

        await creerNotification(
          client._id,
          'aplus_signal',
          (score >= 9 ? '🏆' : '⭐') + ' Setup A+ ' + parsed.decision + ' ' + (parsed.instrument || 'XAUUSD'),
          'Score ' + score + '/10 — ' + (parsed.raisonCourte || 'Setup A+ détecté par l\'IA'),
          {
            decision: parsed.decision,
            instrument: parsed.instrument || 'XAUUSD',
            entree: parsed.entree,
            sl: parsed.sl,
            tp1: parsed.tp1,
            tp2: parsed.tp2,
            tp3: parsed.tp3,
            score: score,
            lots: lotsClient,
            montantRisque: montantClient,
            risquePct: (score >= 8 ? 3 : score >= 6 ? 2 : 1),
            sourceAnalysisId: analyseId
          }
        );
      } catch(e) { console.log('[ALERTE-NOTIF] Erreur ' + client.email + ':', e.message); }
    }

    // ✅ FIX SPAM : envoi séquentiel avec délai (évite le throttling Brevo + meilleure délivrabilité)
    // Envoi 1 par 1 avec 300ms d'intervalle max — pour 50 clients = ~15s total, acceptable
    let envoyes = 0, echecs = 0;
    for (const client of clients) {
      try {
        // ✅ FIX SPAM : sujet sans emojis agressifs, sans majuscules excessives, sans pipe
        // Les mots "URGENT", "DÉTECTÉ", "🔥" en from → score spam très élevé
        const sujetPropre = (isBuy ? '[BUY]' : '[SELL]') + ' ' + instrument + ' — Signal score ' + score + '/10 — J4keIA';

        await transporter.sendMail({
          // ✅ FIX SPAM : pas d'emoji dans le nom d'expéditeur
          from: '"J4keIA Trading" <' + process.env.BREVO_SENDER + '>',
          to: client.email,
          subject: sujetPropre,
          // ✅ FIX RGPD/SPAM : header List-Unsubscribe obligatoire depuis Gmail 2024
          // Sans ça → bouton "Se désabonner" absent → utilisateurs cliquent "Spam"
          headers: {
            'List-Unsubscribe': '<mailto:' + process.env.BREVO_SENDER + '?subject=unsubscribe>',
            'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
            'X-Entity-Ref-ID': analyseId || ('signal-' + Date.now())
          },
          html: htmlEmail
        });
        envoyes++;
        console.log('[ALERTE-EMAIL] ✅ Envoyé à ' + client.email);
        // Petit délai entre chaque envoi pour ne pas throttler Brevo
        await new Promise(r => setTimeout(r, 300));
      } catch(err) {
        echecs++;
        console.log('[ALERTE-EMAIL] ❌ Échec pour ' + client.email + ' : ' + err.message);
      }
    }
    console.log('[ALERTE-EMAIL] Broadcast terminé — ' + envoyes + ' envoyés, ' + echecs + ' échecs');

  } catch(err) {
    // Ne JAMAIS crasher l'analyse à cause d'un email
    console.log('[ALERTE-EMAIL] Erreur générale:', err.message);
  }
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
    // ✅ FIX BUG : setHours() utilisait l'heure locale serveur (pas UTC)
    // → début du jour décalé si serveur pas en UTC. Fix : UTC explicite.
    const debutJour = new Date();
    debutJour.setUTCHours(0, 0, 0, 0);

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
      } else if (a.feedbackResult === 'sl' && a.lots && a.slPips && a.entree && a.sl) {
        // ✅ FIX BUG : estimation perte via distance réelle entrée-SL (avant: hardcodé XAU uniquement)
        const dist = Math.abs(parseFloat(a.entree) - parseFloat(a.sl));
        const inst = (a.instrument || 'XAUUSD').toUpperCase();
        // Valeur par lot selon instrument (cohérent avec calculerLots)
        let valParLot;
        if (inst.includes('XAU')) valParLot = 100;
        else if (inst.includes('JPY')) valParLot = 909;
        else if (inst.includes('NAS') || inst.includes('US100') || inst.includes('SPX') || inst.includes('US500')) valParLot = 1;
        else valParLot = 100000;
        const perteEstimee = dist * valParLot * parseFloat(a.lots);
        if (!isNaN(perteEstimee) && perteEstimee > 0) {
          perteJour += perteEstimee;
          nbSL++;
        }
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

// ═══════════════════════════════════════════════════════════════════
// 🎯 TP PARTIEL 3-TIER (V2)
// ═══════════════════════════════════════════════════════════════════
// Remplace l'ancien gererTpPartielsEtBE() (50/50 + BE pile entrée).
// Nouveau système :
//   - Distribution selon score : A+ (40/30/30), A (50/30/20), B (70/30/0)
//   - SL → BE + buffer (ATR×0.3, mini 2$ XAU) après TP1
//   - SL → lock 50% du gain TP1 après TP2
//   - Trailing structurel sur swings M5 pour le runner
// Wrapper TP partiels : 1 tick toutes les 5 min (économie MetaApi)
async function gererTpPartielsWrapper() {
  await gererTpPartiels3Tier({
    metaApi, db, analysesDb, positionsTrackingDb,
    creerNotification: typeof creerNotification === 'function' ? creerNotification : null
  });
}

// Cleanup auto du tracking : supprime les entries vieilles de 7 jours
async function cleanupTracking() {
  try {
    const il_y_a_7j = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    await positionsTrackingDb.removeAsync({ createdAt: { $lt: il_y_a_7j } }, { multi: true });
  } catch(e) {}
}

// Lancer toutes les 90s (un peu plus rapide pour ne pas rater TP2)
// Économie MetaApi : 1 tick toutes les 5 min
// (capture les TP qui se forment sur > 5 min, économise massivement les deploys)
setInterval(gererTpPartielsWrapper, 5 * 60 * 1000);
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
// ÉCONOMIE : 5 min → 30 min (apprentissage pas urgent, économise ~83% des appels)
setInterval(surveillerTradesEtApprendre, 30 * 60 * 1000);

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
        // ✅ FIX BUG 13 : ne pas utiliser -1 comme fallback (post-mortem déclenché à tort)
        // On exige soit un tradeProfit réel, soit on calcule depuis SL réel via MetaApi
        let perteEstimee = null;
        if (typeof analyse.tradeProfit === 'number' && analyse.tradeProfit < 0) {
          perteEstimee = analyse.tradeProfit;
        } else if (analyse.entree && analyse.sl && analyse.lots) {
          // Calcul fiable : distance × valeur par lot
          const dist = Math.abs(parseFloat(analyse.entree) - parseFloat(analyse.sl));
          const inst = (analyse.instrument || '').toUpperCase();
          const valeurParLot = inst.includes('XAU') ? 100 : inst.includes('JPY') ? 909 : 100000;
          perteEstimee = -(dist * valeurParLot * parseFloat(analyse.lots));
        }
        // Si on n'a pas pu calculer, on skip le post-mortem (au lieu de mettre -1)
        if (perteEstimee === null) {
          console.log('[POST-MORTEM] Skip analyse ' + analyse._id + ' : pas de tradeProfit ni de données pour calculer la perte');
          return res.json({ ok: true, postMortemSkipped: true });
        }
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

  // ✅ FIX BUG 11 : déduplication analyses simultanées
  // Empêche le double-clic / appels parallèles du même user
  if (!global._analysesEnCours) global._analysesEnCours = new Set();
  if (global._analysesEnCours.has(req.session.userId)) {
    allFiles.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });
    return res.status(429).json({
      error: 'analysis_in_progress',
      message: '⏳ Une analyse est déjà en cours. Patiente quelques secondes avant de relancer.'
    });
  }
  global._analysesEnCours.add(req.session.userId);
  // Auto-cleanup après 60s au cas où la requête se bloque
  const cleanupTimer = setTimeout(() => global._analysesEnCours.delete(req.session.userId), 60000);

  try {
    // ✅ FIX BUG : _analysisLocks était redondant avec global._analysesEnCours (double dédup)
    // Retiré : le seul système actif est global._analysesEnCours (libéré dans le finally)
    const _userId = req.session.userId;

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
        return res.json({ error: 'paiement_en_retard', message: '⚠️ Abonnement expiré — Contacte @bigtazz pour renouveler ton accès hebdomadaire.' });
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

    // ─── Anti-tilt : compter pertes consécutives du jour ──────────
    const aujourdhui = new Date(); aujourdhui.setHours(0, 0, 0, 0);
    let consecutiveLosses = 0;
    try {
      const tradesAuj = await analysesDb.findAsync({
        userId: req.session.userId,
        createdAt: { $gte: aujourdhui },
        tradeProfit: { $exists: true }
      });
      const triés = tradesAuj.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      for (const t of triés) {
        if (typeof t.tradeProfit === 'number' && t.tradeProfit < 0) consecutiveLosses++;
        else break;
      }
    } catch(e) { consecutiveLosses = 0; }

    // ─── Kill zone granulaire ─────────────────────────────────────
    const killZone = ict.getKillZone();

    // ─── Bloc règles strict/laxiste ───────────────────────────────
    const blocReglesV2 = promptRules.getReglesText({
      killZoneName: killZone.name,
      sessionActive,
      consecutiveLosses
    });

    // ═══════════════════════════════════════════════════════════════
    // 🛡️ FIX problème 3 : DÉTECTION DE CONFLIT CONTEXTUEL pré-IA
    // Si dealing range et structure pointent dans des directions opposées
    // sans MSS récent qui les réconcilierait → on ne consulte même pas Claude
    // ═══════════════════════════════════════════════════════════════
    let conflitDetecte = false;
    let raisonConflit = null;
    if (global._ictCache && global._ictCache[req.session.userId]) {
      const cache = global._ictCache[req.session.userId];
      // Cache valide < 5 min
      if (cache.time && (Date.now() - cache.time) < 5 * 60 * 1000) {
        const a = cache.analyse;
        const dr = a?.dealingRange;
        const sM15 = a?.structureM15;
        if (dr && sM15) {
          const drBullish = dr.zone === 'DISCOUNT';
          const drBearish = dr.zone === 'PREMIUM';
          const structBullish = sM15.trend === 'UP' || sM15.event?.type === 'MSS_BULLISH' || sM15.event?.type === 'BOS_BULLISH';
          const structBearish = sM15.trend === 'DOWN' || sM15.event?.type === 'MSS_BEARISH' || sM15.event?.type === 'BOS_BEARISH';

          // Conflit : zone dit BUY mais structure dit DOWN sans MSS_BULLISH
          if (drBullish && structBearish && sM15.event?.type !== 'MSS_BULLISH') {
            conflitDetecte = true;
            raisonConflit = 'Zone DISCOUNT (favorise BUY) mais structure M15 ' + sM15.trend + ' (favorise SELL) sans MSS_BULLISH récent → contexte contradictoire';
          }
          // Conflit inverse : zone PREMIUM mais structure UP
          if (drBearish && structBullish && sM15.event?.type !== 'MSS_BEARISH') {
            conflitDetecte = true;
            raisonConflit = 'Zone PREMIUM (favorise SELL) mais structure M15 ' + sM15.trend + ' (favorise BUY) sans MSS_BEARISH récent → contexte contradictoire';
          }
        }
      }
    }

    if (conflitDetecte) {
      console.log('[CONFLIT-CONTEXTUEL] ' + raisonConflit + ' — analyse Claude évitée');
      const reponseConflit = {
        decision: 'NE PAS TRADER',
        score: 4,
        commentaire: 'Contexte contradictoire détecté côté serveur : ' + raisonConflit,
        instrument: req.body.instrument || 'XAUUSD',
        contexteContradictoire: true,
        conflitRaison: raisonConflit
      };
      try { await analysesDb.insertAsync({ ...reponseConflit, userId: req.session.userId, createdAt: new Date() }); } catch(e) {}
      return res.json(reponseConflit);
    }

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

${blocReglesV2}
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
  "drawOnLiquidity": "<cible DOL identifiée ex 'EQH @ 4725' ou 'NONE'>",
  "dolType": "<EQH | EQL | ASIAN_HIGH | ASIAN_LOW | PREVIOUS_HIGH | PREVIOUS_LOW | NONE>",
  "premiumDiscount": "<DISCOUNT | PREMIUM | EQUILIBRIUM>",
  "structureEvent": "<MSS_BULLISH | MSS_BEARISH | BOS_BULLISH | BOS_BEARISH | NONE>",
  "structureLevel": "<niveau cassé si event ou null>",
  "obQuality": "<HIGH | MEDIUM | LOW | NONE>",
  "sweepDetected": "<description sweep récent ou 'AUCUN'>",
  "slUnit": "<dollars | pips — UNITÉ EXACTE du SL en valeur absolue, ne pas mélanger>",
  "slDistance": "<distance SL en valeur absolue dans l'unité ci-dessus>",
  "killZoneActive": "<${killZone.name}>",
  "scoreContext": "<X/7 — DOL+P/D+MSS+H1>",
  "scorePattern": "<X/6 — CRT+OB+FVG+sweep>",
  "scoreTiming": "<X/2 — kill zone>",
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
      system: 'Tu es un assistant trading expert ICT/SMC. Tu utilises systematiquement les concepts: Draw on Liquidity, Premium/Discount, Market Structure Shift, kill zones, Order Block validation. Tu reponds UNIQUEMENT avec du JSON valide, sans aucun texte avant ou apres, sans backticks, sans markdown. Juste le JSON brut commencant par { et finissant par }.',
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

    // ─── FORCER RR ET DIRECTION CÔTÉ SERVEUR (R:R adaptatif selon score) ─
    if (parsed.entree && parsed.sl && parsed.decision !== 'NE PAS TRADER') {
      const entree = parseFloat(parsed.entree);
      const sl = parseFloat(parsed.sl);
      const isBuy = parsed.decision === 'BUY';

      // ─── FIX problème 6 : VALIDATION DIRECTION SL ─────────────────
      // Si BUY mais sl > entree → erreur grave de l'IA, on annule le trade
      // (un SL "au-dessus" pour BUY signifie qu'elle s'est trompée)
      if (isBuy && sl >= entree) {
        console.log('[SL-DIRECTION] BUY mais SL ' + sl + ' >= entrée ' + entree + ' → trade annulé');
        parsed.decision = 'NE PAS TRADER';
        parsed.slDirectionAlerte = 'SL incohérent : pour un BUY le SL doit être SOUS l\'entrée. SL=' + sl + ' Entrée=' + entree;
      } else if (!isBuy && sl <= entree) {
        console.log('[SL-DIRECTION] SELL mais SL ' + sl + ' <= entrée ' + entree + ' → trade annulé');
        parsed.decision = 'NE PAS TRADER';
        parsed.slDirectionAlerte = 'SL incohérent : pour un SELL le SL doit être AU-DESSUS de l\'entrée. SL=' + sl + ' Entrée=' + entree;
      }

      if (entree && sl && parsed.decision !== 'NE PAS TRADER') {
        const dist = Math.abs(entree - sl);
        const slCorrige = isBuy ? entree - dist : entree + dist;
        // R:R adaptatifs : setup A+ = TP plus ambitieux, setup B = plus défensif
        const score = parseFloat(parsed.score) || 7;
        // ✅ FIX BUG : rr1 était 1.5 dans les deux cas (score>=9 et score 7-8) — pas de différenciation A+
        const rr1 = score >= 9 ? 2.0 : (score >= 7 ? 1.5 : 1.0);
        const rr2 = score >= 9 ? 2.5 : (score >= 7 ? 2.0 : 2.0);
        const rr3 = score >= 9 ? 4.0 : (score >= 7 ? 3.0 : 3.0);
        const tp1 = isBuy ? entree + dist * rr1 : entree - dist * rr1;
        const tp2 = isBuy ? entree + dist * rr2 : entree - dist * rr2;
        const tp3 = isBuy ? entree + dist * rr3 : entree - dist * rr3;
        parsed.sl = slCorrige.toFixed(2);
        parsed.tp1 = tp1.toFixed(2);
        parsed.tp2 = tp2.toFixed(2);
        parsed.tp3 = tp3.toFixed(2);
        parsed.slPips = Math.round(dist * 10) / 10;
        parsed.tp1Pips = Math.round(dist * rr1 * 10) / 10;
        parsed.tp2Pips = Math.round(dist * rr2 * 10) / 10;
        parsed.tp3Pips = Math.round(dist * rr3 * 10) / 10;
      }
    }

    // ─── GARDE SCORE MINIMUM CÔTÉ SERVEUR ──────────────────────
    // Même si l'IA rate la règle, on force le refus si score < 6
    if (parsed.decision !== 'NE PAS TRADER' && (parsed.score || 0) < 6) {
      console.log('[SCORE-GUARD] Score ' + parsed.score + ' < 6 → NE PAS TRADER forcé côté serveur');
      parsed.decision = 'NE PAS TRADER';
      parsed.scoreGuardAlerte = 'Score trop faible (' + parsed.score + '/10) — minimum requis : 6/10 pour trader';
    }

    // ═════════════════════════════════════════════════════════════
    // 🛡️ HARD-BLOCKS POST-IA (problèmes 1 + 4 du document)
    // Ces validations vérifient la cohérence entre la décision Claude
    // et les champs ICT qu'il a lui-même retournés. Si Claude se contredit
    // (ex: BUY en PREMIUM sans MSS), on annule.
    // ═════════════════════════════════════════════════════════════
    if (parsed.decision === 'BUY' || parsed.decision === 'SELL') {
      const hardBlocks = [];
      const isBuy = parsed.decision === 'BUY';

      // BLOCK 1 : BUY en PREMIUM sans MSS_BULLISH = piège classique
      if (isBuy && parsed.premiumDiscount === 'PREMIUM' &&
          parsed.structureEvent !== 'MSS_BULLISH' && parsed.structureEvent !== 'BOS_BULLISH') {
        hardBlocks.push('BUY en zone PREMIUM sans MSS bullish — achat au sommet du range');
      }
      // BLOCK 2 : SELL en DISCOUNT sans MSS_BEARISH
      if (!isBuy && parsed.premiumDiscount === 'DISCOUNT' &&
          parsed.structureEvent !== 'MSS_BEARISH' && parsed.structureEvent !== 'BOS_BEARISH') {
        hardBlocks.push('SELL en zone DISCOUNT sans MSS bearish — vente en bas du range');
      }
      // ✅ FIX BUG 10 : parsed.rsi/rsiM15 jamais dans la réponse IA → block RSI inopérant
      // On utilise le cache market data (déjà calculé dans verifierProtectionsAvancees)
      // Note : verifierProtectionsAvancees gère déjà ce cas — ce block est un double-check
      // pour les situations où le cache n'est pas dispo. On utilise parsed.rsiUtilise comme proxy.
      const rsiM15Str = String(parsed.rsiUtilise || '');
      const rsiM15Match = rsiM15Str.match(/M15[^\d]*(\d+(?:\.\d+)?)/);
      const rsiM15 = rsiM15Match ? parseFloat(rsiM15Match[1]) : 0;
      if (rsiM15 > 0) {
        if (isBuy && rsiM15 > 78) hardBlocks.push('RSI M15 ' + rsiM15.toFixed(1) + ' > 78 (surachat extrême) avec BUY');
        if (!isBuy && rsiM15 < 22) hardBlocks.push('RSI M15 ' + rsiM15.toFixed(1) + ' < 22 (survente extrême) avec SELL');
      }

      if (hardBlocks.length > 0) {
        console.log('[HARD-BLOCK] ' + parsed.decision + ' annulé : ' + hardBlocks.join(' | '));
        parsed.decision = 'NE PAS TRADER';
        parsed.hardBlockAlerte = 'Trade annulé par hard-block serveur : ' + hardBlocks.join(' | ');
      }
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

      // ✅ FIX BUG 5 : utiliser la distance directe |entrée - SL| en dollars
      // (plus fiable que les heuristiques sur slPips)
      let slDistanceDollars = null;
      if (parsed.entree && parsed.sl) {
        const distDirect = Math.abs(parseFloat(parsed.entree) - parseFloat(parsed.sl));
        if (distDirect > 0 && !isNaN(distDirect)) slDistanceDollars = distDirect;
      }
      parsed.lots = calculerLots(capital, risquePct, parsed.slPips, parsed.instrument || '', slDistanceDollars);
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

    // ✅ FIX BUG : slPips, entree (champ 'entree'), risquePct manquaient → getFacteurRisque
    // et le post-mortem ne pouvaient pas calculer les pertes estimées correctement
    await analysesDb.insertAsync({
      _id: analysisId,
      userId: req.session.userId,
      decision: parsed.decision,
      entry: parsed.entree,    // champ 'entry' pour compatibilité historique
      entree: parsed.entree,   // champ 'entree' pour les fonctions qui lisent ce champ
      sl: parsed.sl,
      tp: parsed.tp1,
      tp2: parsed.tp2,
      tp3: parsed.tp3,
      score: parsed.score,
      instrument: parsed.instrument,
      lots: parsed.lots,
      slPips: parsed.slPips,           // ✅ FIX : manquait → perte estimée = 0
      risquePct: parsed.risquePct,     // ✅ FIX : manquait → contexte drawdown incorrect
      montantRisque: parsed.montantRisque,
      manipulation: parsed.manipulation,
      crt: parsed.crt,
      crtKasper: parsed.crtKasper || null,
      rangeHaut: parsed.rangeHaut,
      rangeBas: parsed.rangeBas,
      ob: parsed.ob || null,
      fvg: parsed.fvg || null,
      entreeLevel: parsed.entreeLevel || null,
      confluences: parsed.confluences || null,
      feedbackResult: null,
      createdAt: new Date()
    });

    if (user.role !== 'admin') await db.updateAsync({ _id: user._id }, { $inc: { analysisCount: 1 } }, {});
    const analysesLeft = analysesRestantes(user);

    // ─── ALERTE EMAIL SETUP A+ (score >= 8, BUY ou SELL) ──────────
    // Lance en arriere-plan : ne bloque PAS la reponse au client
    if ((parsed.score || 0) >= 8 && (parsed.decision === 'BUY' || parsed.decision === 'SELL')) {
      envoyerAlerteSetupAPlus(parsed, analysisId).catch(e =>
        console.log('[ALERTE-EMAIL] Erreur silencieuse:', e.message)
      );
    }

    res.json({ ...parsed, analysesLeft, analysisId });

  } catch (err) {
    allFiles.forEach(f => { try { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); } catch(e){} });
    // ✅ FIX BUG : vérifier que la réponse n'a pas déjà été envoyée (évite Cannot set headers)
    if (!res.headersSent) res.status(500).json({ error: 'Erreur: ' + err.message });
  } finally {
    // ✅ FIX BUG 11 : libérer le slot d'analyse en cours
    clearTimeout(cleanupTimer);
    if (global._analysesEnCours) global._analysesEnCours.delete(req.session.userId);
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

// ─── POST /admin/alerte-email : envoyer manuellement une alerte email ─
// L'admin peut tester ou forcer un broadcast même sans analyse IA
app.post('/admin/alerte-email', checkAdmin, async (req, res) => {
  try {
    const { decision, instrument, entree, sl, tp1, tp2, tp3, score, raison, lots } = req.body;
    if (!decision || !instrument || !score) {
      return res.status(400).json({ error: 'Champs requis : decision, instrument, score' });
    }
    const fakeParsed = { decision, instrument, entree, sl, tp1, tp2, tp3, score: parseFloat(score), lots,
      raisonCourte: raison || 'Setup manuel envoyé par l\'admin' };
    await envoyerAlerteSetupAPlus(fakeParsed, 'ADMIN-' + Date.now());
    res.json({ success: true, message: 'Alerte envoyée à tous les clients abonnés' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
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
      // ✅ FIX BUG : ancien calcul donnait parfois seulement 1-2 jours si validation
      // en fin de semaine (ex: dimanche → paidUntil = ce soir même).
      // Nouvelle logique : toujours 7 jours PLEINS → dimanche soir de la semaine qui suit J+7.
      // Ex: validation lundi → expire dimanche dans 13 jours (semaine complète garantie)
      // Ex: validation vendredi → expire dimanche dans 9 jours (idem)
      const now = new Date();
      const plusSeptJours = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      const dayApres7 = plusSeptJours.getUTCDay(); // 0=dim, 1=lun...
      // Aller jusqu'au dimanche suivant J+7
      const daysUntilSundayAfter7 = dayApres7 === 0 ? 0 : 7 - dayApres7;
      const nextSunday = new Date(plusSeptJours);
      nextSunday.setUTCDate(plusSeptJours.getUTCDate() + daysUntilSundayAfter7);
      nextSunday.setUTCHours(23, 59, 59, 999);
      paidUntil = nextSunday.toISOString();
      console.log('[PAYMENT] paidUntil calculé : ' + paidUntil + ' (7j complets garantis)');
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