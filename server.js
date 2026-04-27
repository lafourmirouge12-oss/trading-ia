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
// SYSTÈME POST-MORTEM : surveille les trades perdants et apprend
// ═══════════════════════════════════════════════════════════════════

// Surveille les positions fermées en perte et flag les analyses correspondantes
async function surveillerTradesPerdants() {
  if (!metaApi) return;
  try {
    // Récupérer les analyses récentes (dernières 7 jours) avec un trade exécuté et pas encore analysées en post-mortem
    const dateLimit = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const analysesAVerifier = await analysesDb.findAsync({
      createdAt: { $gte: dateLimit },
      decision: { $in: ['BUY', 'SELL'] },
      postMortemStatut: { $exists: false }
    });

    if (analysesAVerifier.length === 0) return;

    // Grouper par utilisateur pour limiter les connexions MetaAPI
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

        // Récupérer l'historique des deals des 7 derniers jours
        const deals = await connection.getDealsByTimeRange(dateLimit, new Date());

        for (const analyse of parUser[userId]) {
          // Trouver un deal correspondant à cette analyse (même symbole, même direction, date après création)
          const symbole = (analyse.instrument || 'XAUUSD').toUpperCase();
          const dealsCorrespondants = (deals || []).filter(d => {
            if (!d.symbol || !d.profit) return false;
            const symbolMatch = d.symbol.toUpperCase().includes(symbole) || symbole.includes(d.symbol.toUpperCase().replace(/-.*/, ''));
            const dateMatch = new Date(d.time) > new Date(analyse.createdAt);
            const directionMatch = (analyse.decision === 'BUY' && d.type === 'DEAL_TYPE_SELL') || (analyse.decision === 'SELL' && d.type === 'DEAL_TYPE_BUY');
            // Note: un deal de fermeture est de type opposé à l'ouverture
            return symbolMatch && dateMatch && directionMatch;
          });

          if (dealsCorrespondants.length === 0) continue;

          // Prendre le deal le plus proche temporellement de l'analyse
          dealsCorrespondants.sort((a, b) => new Date(a.time) - new Date(b.time));
          const deal = dealsCorrespondants[0];
          const profit = parseFloat(deal.profit);

          if (profit < 0) {
            // Trade perdant → marquer pour post-mortem
            await analysesDb.updateAsync(
              { _id: analyse._id },
              { $set: {
                postMortemStatut: 'requis',
                tradeProfit: profit,
                tradeClotureTemps: deal.time,
                tradeDealId: deal.id
              }}
            );
            console.log('[POSTMORTEM] Trade perdant détecté pour analyse ' + analyse._id + ' : ' + profit + '$');
          } else {
            // Trade gagnant ou breakeven → on marque juste comme traité
            await analysesDb.updateAsync(
              { _id: analyse._id },
              { $set: { postMortemStatut: 'gagnant', tradeProfit: profit }}
            );
          }
        }

        if (deployedHere) {
          try { await account.undeploy(); trackUndeploy(account.id); } catch(e) {}
        }
      } catch(err) {
        console.log('[POSTMORTEM] Erreur user ' + userId + ' : ' + err.message);
      }
    }
  } catch(err) {
    console.log('[POSTMORTEM] Erreur surveillance:', err.message);
  }
}

// Lancer la surveillance toutes les 2 minutes
setInterval(surveillerTradesPerdants, 2 * 60 * 1000);

// Récupère les leçons à injecter dans le prompt (toutes les leçons, max 10 plus récentes par user)
async function getLeconsPourPrompt(userId) {
  try {
    const lecons = await leconsDb.findAsync({ userId });
    lecons.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const top = lecons.slice(0, 10);
    if (top.length === 0) return '';
    let txt = '\n═══════════════════════════════════════════════════════════════\n';
    txt += '📚 LEÇONS APPRISES DES TRADES PERDANTS PRÉCÉDENTS — À RESPECTER\n';
    txt += '═══════════════════════════════════════════════════════════════\n';
    txt += 'Voici les erreurs commises sur des trades précédents qui ont touché le SL.\n';
    txt += 'AVANT de proposer ce nouveau trade, vérifie que tu ne refais PAS la même erreur :\n\n';
    top.forEach((l, i) => {
      txt += `${i + 1}. [${l.setupType || 'Setup'}] ${l.lecon}\n`;
      if (l.signalManque) txt += `   Signal qu'il fallait voir : ${l.signalManque}\n`;
      txt += '\n';
    });
    txt += '═══════════════════════════════════════════════════════════════\n';
    return txt;
  } catch(err) {
    console.log('[LECONS] Erreur récupération:', err.message);
    return '';
  }
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
      { $set: { feedbackResult: result } },
      {}
    );
    res.json({ success: true });
  } catch(e) { res.json({ error: e.message }); }
});

// ─── ROUTES POST-MORTEM ─────────────────────────────────────────────

// Liste les analyses qui attendent un post-mortem (trades perdants)
app.get('/postmortem/pending', checkAuth, async (req, res) => {
  try {
    const enAttente = await analysesDb.findAsync({
      userId: req.session.userId,
      postMortemStatut: 'requis'
    });
    enAttente.sort((a, b) => new Date(b.tradeClotureTemps || b.createdAt) - new Date(a.tradeClotureTemps || a.createdAt));
    res.json({ count: enAttente.length, analyses: enAttente });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// Soumet un screen pour analyse post-mortem d'un trade perdant
app.post('/postmortem/:analysisId', checkAuth, upload.single('screen'), async (req, res) => {
  try {
    const analyse = await analysesDb.findOneAsync({
      _id: req.params.analysisId,
      userId: req.session.userId
    });
    if (!analyse) return res.status(404).json({ error: 'Analyse introuvable' });
    if (analyse.postMortemStatut !== 'requis') return res.status(400).json({ error: 'Pas de post-mortem requis pour ce trade' });
    if (!req.file) return res.status(400).json({ error: 'Screen manquant' });

    // Lire le screen en base64
    const imageData = fs.readFileSync(req.file.path);
    const base64Image = imageData.toString('base64');
    const mimeType = req.file.mimetype || 'image/png';

    // Construire le prompt post-mortem avec le contexte de l'analyse originale
    const promptText = `Tu es un trader expert Smart Money ICT. On va analyser un trade qui a touché le SL pour comprendre l'erreur.

CONTEXTE DU TRADE PERDANT :
- Instrument : ${analyse.instrument || 'XAUUSD'}
- Direction : ${analyse.decision}
- Entrée : ${analyse.entry}
- SL : ${analyse.sl}
- TP1 : ${analyse.tp}
- Score initial : ${analyse.score}/10
- Range asiatique au moment de l'analyse : ${analyse.rangeBas || '?'} - ${analyse.rangeHaut || '?'}
- Manipulation détectée à l'analyse : ${analyse.manipulation || 'non précisé'}
- CRT au moment de l'analyse : ${analyse.crt || 'non précisé'}
- Perte : ${analyse.tradeProfit}$
- Date analyse : ${new Date(analyse.createdAt).toLocaleString('fr-FR')}
- Date clôture : ${analyse.tradeClotureTemps ? new Date(analyse.tradeClotureTemps).toLocaleString('fr-FR') : 'inconnue'}

L'utilisateur t'envoie un screen du graphique au moment où le SL a été touché.

TA MISSION :
1. Analyse le screen et identifie CE QUI A FOIRÉ
2. Identifie LE SIGNAL qu'il fallait voir avant pour éviter ce trade
3. Formule une LEÇON courte et actionnable (1-2 phrases max) qui sera utilisée pour les futures analyses

Réponds UNIQUEMENT en JSON valide, sans texte avant ni après :
{
  "ce_qui_a_foire": "explication courte de l'erreur (1 phrase)",
  "signal_manque": "le signal qu'il fallait voir avant (1 phrase concrète)",
  "lecon": "règle actionnable à respecter dans les futures analyses (1 phrase impérative)",
  "setup_type": "type de setup (ex: CRT Kasper, OB+FVG, Range asiatique, etc.)"
}`;

    const response = await anthropic.messages.create({
      model: 'claude-opus-4-5',
      max_tokens: 800,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: mimeType, data: base64Image }},
          { type: 'text', text: promptText }
        ]
      }]
    });

    // Nettoyer le fichier uploadé
    try { fs.unlinkSync(req.file.path); } catch(e) {}

    const rawText = response.content[0].text.trim();
    const jsonMatch = rawText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return res.status(500).json({ error: 'Réponse IA non parseable', raw: rawText });

    let leconParsed;
    try {
      leconParsed = JSON.parse(jsonMatch[0]);
    } catch(e) {
      return res.status(500).json({ error: 'JSON invalide', raw: rawText });
    }

    // Stocker la leçon
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
      createdAt: new Date()
    });

    // Marquer l'analyse comme post-mortem fait
    await analysesDb.updateAsync(
      { _id: analyse._id },
      { $set: { postMortemStatut: 'analyse', leconId }}
    );

    console.log('[POSTMORTEM] Leçon enregistrée pour analyse ' + analyse._id);
    res.json({ success: true, lecon: leconParsed });

  } catch(err) {
    if (req.file) try { fs.unlinkSync(req.file.path); } catch(e) {}
    console.log('[POSTMORTEM] Erreur:', err.message);
    res.status(500).json({ error: 'Erreur post-mortem : ' + err.message });
  }
});

// Liste toutes les leçons du user (pour affichage sur le site)
app.get('/postmortem/lecons', checkAuth, async (req, res) => {
  try {
    const lecons = await leconsDb.findAsync({ userId: req.session.userId });
    lecons.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ count: lecons.length, lecons });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// Supprimer une leçon (si l'user juge qu'elle est mauvaise)
app.delete('/postmortem/lecons/:leconId', checkAuth, async (req, res) => {
  try {
    await leconsDb.removeAsync({ _id: req.params.leconId, userId: req.session.userId });
    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
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

    // Récupérer les leçons des trades perdants précédents pour ce user
    const leconsBlock = await getLeconsPourPrompt(req.session.userId);

    content.push({
      type: 'text',
      text: `Tu es un trader Smart Money ICT professionnel avec 15 ans d'expérience.${capital ? ` Capital du trader: $${capital}.` : ''}
${leconsBlock}

═══════════════════════════════════════════════════════════════
🕐 CONTEXTE TEMPOREL — OBLIGATOIRE À RESPECTER
═══════════════════════════════════════════════════════════════
${sessionWarning}
SESSION ACTIVE: ${sessionActive}
═══════════════════════════════════════════════════════════════

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
- Le SL doit être placé JUSTE AU-DELÀ du sweep de la bougie 2 M15 + 5-10$ buffer minimum
  → Exemple BUY : SL = low de bougie 2 M15 - buffer (min 5$)
  → Exemple SELL : SL = high de bougie 2 M15 + buffer (min 5$)

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

SL DOIT ÊTRE PRÉCIS MAIS PAS TROP SERRÉ :
- BUY : SL juste sous le low de la zone d'entrée (OB, key candle, etc.) - 5-10$ buffer minimum
- SELL : SL juste au-dessus du high de la zone - 5-10$ buffer minimum
- Avec entrée sniper, SL typique XAUUSD = 8-20$ (jamais moins de 5$, le marché est volatil)
- Un SL trop serré (< 5$) = se faire sortir par le spread ou une micro-mèche → INTERDIT
- R:R cible minimum 1:3, idéal 1:4 ou 1:5
═══════════════════════════════════════════════════════════════
🔥 ═══════════════════════════════════════════════════════════════
CONFLUENCE CRT + FVG + ORDER BLOCK = SETUP A+ (ICT PRO)
═══════════════════════════════════════════════════════════════
Quand un CRT Kasper se forme, la bougie 3 (celle qui CASSE l'extrême
opposé) crée souvent un FVG ET un Order Block au même endroit.
C'est LE setup le plus puissant en ICT/SMC. À chercher en priorité.

📐 DÉFINITIONS PRÉCISES :

ORDER BLOCK (OB) — Zone où le smart money a accumulé/distribué :
• OB BULLISH = la DERNIÈRE bougie BAISSIÈRE avant un mouvement haussier impulsif
  → Zone d'entrée BUY = entre le HIGH et le LOW de cette bougie rouge
• OB BEARISH = la DERNIÈRE bougie HAUSSIÈRE avant un mouvement baissier impulsif
  → Zone d'entrée SELL = entre le HIGH et le LOW de cette bougie verte
• Plus la bougie OB est petite et l'impulsion suivante grande, plus le OB est puissant

FVG (Fair Value Gap) — Imbalance dans le prix :
• FVG BULLISH = sur 3 bougies consécutives, le LOW de la bougie 3 > HIGH de la bougie 1
  → Le gap entre HIGH bougie 1 et LOW bougie 3 = FVG haussier (à combler)
• FVG BEARISH = HIGH bougie 3 < LOW bougie 1
  → Gap entre LOW bougie 1 et HIGH bougie 3 = FVG baissier
• Le prix RETOURNE souvent combler les FVG avant de continuer

🎯 COMMENT COMBINER CRT + FVG + OB :

ÉTAPE 1 — Identifier le CRT Kasper sur M15 (3 bougies)
ÉTAPE 2 — Sur la bougie 3 (la bougie de BREAK), identifier :
   • L'OB = la dernière bougie OPPOSÉE à la direction du break
     (pour CRT BULLISH = la dernière bougie rouge avant le break vert)
     (pour CRT BEARISH = la dernière bougie verte avant le break rouge)
   • Le FVG = le gap créé par la bougie 3 (si elle est forte)

ÉTAPE 3 — Vérifier la CONFLUENCE :
   • Le OB et le FVG sont-ils sur la MÊME ZONE de prix ?
   • Cette zone correspond-elle au RETEST de la key candle CRT ?
   • Si OUI aux 3 → SETUP A+ (3 confluences alignées)

🎯 PLACEMENT OPTIMAL avec confluence CRT + FVG + OB :

POUR UN BUY (CRT BULLISH) :
• Entrée 1 (idéale) : haut du FVG bullish (zone haute du gap)
• Entrée 2 (alternative) : haut de l'OB bullish (zone haute de la dernière bougie rouge)
• Entrée 3 (sécurisée) : key candle high CRT (retest du break)
→ Choisis le niveau le PLUS PROCHE du prix actuel parmi ces 3

• SL : sous le LOW de l'OB - 2-3 pips de buffer
  (si l'OB est cassé, le setup est invalidé, donc SL logique)
• TP1 : avant la prochaine zone de liquidité (R:R 1:2 min)
• TP2 : sur le high majeur précédent (R:R 1:3)

POUR UN SELL (CRT BEARISH) :
• Entrée 1 (idéale) : bas du FVG bearish
• Entrée 2 (alternative) : bas de l'OB bearish
• Entrée 3 (sécurisée) : key candle low CRT
• SL : au-dessus du HIGH de l'OB + buffer

📊 SCORING DE LA CONFLUENCE :
• CRT + FVG + OB tous alignés → score 9-10 (setup A+, lot boost autorisé)
• CRT + (FVG ou OB) → score 7-8 (très bon setup)
• CRT seul sans FVG ni OB clair → score 5-6 (setup correct mais moins fiable)
• OB + FVG sans CRT → score 6-7 (setup ICT classique, valide)

⚠️ RÈGLES IMPORTANTES :
• Le FVG doit être FRAIS (pas déjà comblé une 1ère fois)
• L'OB doit être proche du prix actuel (pas à 50+ pips)
• Si plusieurs OB visibles, prends celui le plus PROCHE de l'entrée CRT
• Privilégie TOUJOURS la zone où FVG + OB se chevauchent (=double confluence)
═══════════════════════════════════════════════════════════════

🛡️ ═══════════════════════════════════════════════════════════════
PROTECTION ANTI-LIQUIDITÉ — CRITICAL POUR ÉVITER LES SL TAPÉS
═══════════════════════════════════════════════════════════════
Le smart money chasse SYSTÉMATIQUEMENT la liquidité avant de partir
dans la vraie direction. Ton job : placer le SL et le TP de manière
à NE PAS être pris dans cette chasse.

🚨 LIQUIDITÉ = zones où ya des stops loss accumulés :
• EQUAL LOWS (plusieurs bougies avec le même low) → liquidité basse
• EQUAL HIGHS (plusieurs bougies avec le même high) → liquidité haute
• Mèches multiples au même niveau → stops accumulés
• Round numbers ($4700, $4750, $4800 sur XAUUSD) → liquidité psychologique
• Anciens swing high/low évidents → magnet à stops
• Niveaux pré-news (avant CPI/NFP) → liquidité juteuse

⚠️ RÈGLES DE PLACEMENT DU SL :
1. AVANT de placer le SL, identifie TOUTES les zones de liquidité
   en-dessous (pour BUY) ou au-dessus (pour SELL) du prix d'entrée
2. Le SL ne doit JAMAIS être placé :
   • PILE sur un equal low/high évident
   • JUSTE au-dessus/sous un round number ($4700 par ex)
   • Au "milieu de nulle part" sans support technique
3. Le SL doit être placé :
   • DERRIÈRE une zone de liquidité (qu'on laisse être chassée d'abord)
   • OU à un niveau structurel évident (low/high majeur protégé)
   • Avec 2-3 pips de buffer de sécurité

EXEMPLE BUY XAUUSD :
- Entrée : 4720 (sur OB)
- Y a 3 mèches qui ont touché 4715 (equal lows) = liquidité
- ❌ MAUVAIS SL : 4714 (juste sous l'equal low → va se faire taper en chasse)
- ✅ BON SL : 4711 (DERRIÈRE l'equal low + buffer → la chasse à 4715
  va se faire mais ton SL tient, puis ça repart en BUY)

⚠️ RÈGLES DE PLACEMENT DU TP :
1. AVANT de placer le TP, identifie les zones de liquidité opposées
   qui vont attirer le prix
2. Le TP doit être placé :
   • LÉGÈREMENT AVANT une grosse zone de liquidité (pour prendre les profits
     avant que le prix se fasse rejeter)
   • OU PILE sur une zone de liquidité majeure (le smart money va y aller)
3. Le TP ne doit JAMAIS être placé :
   • Juste APRÈS une zone de liquidité forte (le prix va rejeter avant)
   • Sur un niveau "rond" sans signification technique

EXEMPLE BUY XAUUSD :
- Entrée 4720, prix actuel 4722
- Y a un swing high majeur à 4750 + equal highs vers 4748 = liquidité haute
- ✅ TP1 : 4744 (avant la liquidité, profits sécurisés)
- ✅ TP2 : 4750 (sur le swing high, le smart money y va)
- ❌ TP3 : 4760 (au-delà → risque de rejet sur la liquidité)

🎯 LOGIQUE FINALE DU PLACEMENT :
- Entrée = sur niveau technique (OB/FVG/key candle/EMA)
- SL = DERRIÈRE la liquidité la plus proche (pas dessus !)
- TP1 = AVANT la prochaine liquidité opposée (R:R min 1:2)
- TP2 = SUR la zone de liquidité opposée majeure (R:R 1:3)
- TP3 = optionnel, sur le prochain niveau structurel

⚠️ AVERTISSEMENT CRITIQUE :
Si tu ne peux pas placer un SL "safe" (toujours derrière une liquidité majeure),
augmente le SL pour passer derrière la liquidité, OU réduis la taille du trade
mentale, OU NE PAS TRADER si la zone est trop dangereuse.
═══════════════════════════════════════════════════════════════

Réponds UNIQUEMENT avec un JSON valide, sans texte avant ou après, sans backticks:

{
  "decision": "BUY" ou "SELL" ou "NE PAS TRADER",
  "session": "<session active au moment de l'analyse: ASIATIQUE / LONDRES / NEW_YORK / FIN_NY>",
  "sessionImpact": "<comment la session influence ce signal: ex 'Session asiatique → range probable, signal rejeté' ou 'Ouverture Londres → signal valide'>",
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
  "sl": "<stop loss — min 50 pips sur XAU/USD (= min $5 de distance)${crtKasperActif ? ', mais si CRT Kasper détecté: SL = juste au-delà du sweep bougie 2 (min 30 pips quand même)' : ''}>",
  "slPips": <pips SL — min 50 sur XAU/USD>,
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
  "ob": "<Order Block: prix exact de la zone OB + direction (haussier/baissier) ou 'Aucun OB clair'>",
  "fvg": "<Fair Value Gap: prix exact du gap + direction ou 'Aucun FVG visible'>",
  "obFvgConfluence": "<OUI si OB et FVG se chevauchent + niveau de prix concerné, NON sinon>",
  "confluenceCrtObFvg": "<si CRT Kasper détecté: décris si CRT + OB + FVG sont alignés sur la même zone — SETUP A+ ou pas>",
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
      max_tokens: 2500,
      system: 'Tu es un assistant trading. Tu reponds UNIQUEMENT avec du JSON valide, sans aucun texte avant ou apres, sans backticks, sans markdown. Juste le JSON brut commencant par { et finissant par }.',
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

    // ─── ANTI-PIÈGE RANGE ASIATIQUE (vérification post-IA) ────
    parsed = verifierPiegeRangeAsiatique(parsed);

    // ─── RÉAJUSTEMENT AUTO DE L'ENTRÉE (vs prix actuel MetaAPI) ───
    parsed = await reajusterEntreeSiNecessaire(parsed, req.session.userId);

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

app.listen(port, () => {
  console.log('✅ Serveur lancé sur http://localhost:' + port);
});