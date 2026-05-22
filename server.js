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

let deployTracker = {}; // { accountId: { deployedAt: ms, login: string } } — sera rechargé au démarrage

// ═══════════════════════════════════════════════════════════════════
// 🛡️ WATCHDOG ULTRA-RENFORCÉ — protection contre les comptes "fantômes"
// ═══════════════════════════════════════════════════════════════════
// Objectif : qu'AUCUN compte MetaApi ne reste deployed > 90s sans raison.
//
// Stratégie multi-couches :
//   1. Tracker en mémoire + persisté sur disque (survit aux restarts)
//   2. Watchdog interne toutes les 30s → undeploy comptes du tracker > 90s
//   3. Boot scan au démarrage → undeploy tous les comptes orphelins
//   4. Hard scan toutes les 10 min → scanne TOUS les comptes MetaApi et
//      undeploy ceux qui sont deployed depuis trop longtemps (FILET ULTIME
//      contre les comptes fantômes que le tracker a perdu)
//
// Persistance : tracker stocké dans deploy-tracker.json toutes les 10s.

const MAX_DEPLOY_MS = 90 * 1000; // 90 secondes max
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
async function watchdogBootScan() {
  if (!metaApi) return;
  console.log('[WATCHDOG] Boot scan en cours...');
  try {
    const accountsApi = metaApi.metatraderAccountApi;
    let allAccounts = [];

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
deployTracker = loadTracker();

if (metaApi) {
  // Watchdog interne : check toutes les 30s
  setInterval(watchdogCheck, WATCHDOG_INTERVAL);
  // Boot scan : 30s après démarrage
  setTimeout(watchdogBootScan, 30 * 1000);
  // HARD SCAN : filet ultime, 10 min
  setInterval(hardScanComptesFantomes, HARD_SCAN_INTERVAL);
  // Sauvegarde tracker toutes les 10s
  setInterval(saveTracker, 10 * 1000);

  console.log('[WATCHDOG] Multi-couches actif : interne 30s, hard scan 10min, max ' + (MAX_DEPLOY_MS/1000) + 's deployed');
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

// ═══ RESOLUTION SYMBOLES UNIFIEE (priorite selon serveur broker) ═══
// ═══ TABLE MAPPING SYMBOLES MULTI-BROKER ═══
// Certains brokers utilisent des noms ALTERNATIFS pour le même actif :
//   - VT Markets : XAUUSD-STD, EURUSD-STD, NAS100, US30
//   - Vantage    : XAUUSD, EURUSD, NAS100, DJ30
//   - IC Markets : XAUUSD, EURUSD, NAS100.cash, US30.cash
//   - Exness     : XAUUSDm (micro), EURUSDm, USTECm
// Si le symbole de base ne marche pas, on essaie ces alternatives.
const SYMBOL_ALIASES = {
  // FIX RaiseFX : utilise 'Gold' (avec G majuscule, sans suffixe) — on ajoute toutes les variantes possibles
  'XAUUSD': ['XAUUSD', 'GOLD', 'Gold', 'gold', 'XAU', 'GOLD.cash', 'XAUUSDm', 'XAU/USD', 'XAUUSD.r', 'XAUUSDx', 'GOLDx', 'XAU.cash', 'XAUUSD.raw', 'XAUUSD-raw', 'GOLD#', 'XAUUSD#', 'XAUUSD.RAW', 'GOLDUSD', 'Gold.spot', 'XAUUSD_SB', 'XAUUSDpro', 'XAUUSD.pro', 'XAUUSD.std', 'XAUUSD.vip', 'XAUUSDc'],
  'XAGUSD': ['XAGUSD', 'SILVER', 'XAG', 'SILVER.cash', 'XAGUSDm', 'XAG/USD'],
  'EURUSD': ['EURUSD', 'EUR/USD', 'EURUSDm'],
  'GBPUSD': ['GBPUSD', 'GBP/USD', 'GBPUSDm'],
  'USDJPY': ['USDJPY', 'USD/JPY', 'USDJPYm'],
  'AUDUSD': ['AUDUSD', 'AUD/USD', 'AUDUSDm'],
  'NZDUSD': ['NZDUSD', 'NZD/USD', 'NZDUSDm'],
  'USDCHF': ['USDCHF', 'USD/CHF', 'USDCHFm'],
  'USDCAD': ['USDCAD', 'USD/CAD', 'USDCADm'],
  'EURJPY': ['EURJPY', 'EUR/JPY', 'EURJPYm'],
  'GBPJPY': ['GBPJPY', 'GBP/JPY', 'GBPJPYm'],
  'EURGBP': ['EURGBP', 'EUR/GBP', 'EURGBPm'],
  'NAS100': ['NAS100', 'USTEC', 'US100', 'NDX100', 'NAS100.cash', 'USTECm', 'USNAS100'],
  'US30':   ['US30', 'DJ30', 'WS30', 'DJ.cash', 'US30.cash', 'DJI30', 'USWS30'],
  'US500':  ['US500', 'SPX500', 'SP500', 'SPX', 'US500.cash', 'USSPX500'],
  'GER40':  ['GER40', 'DAX40', 'DE40', 'GER30', 'DAX.cash', 'DEU40'],
  'UK100':  ['UK100', 'FTSE100', 'FTSE', 'UK100.cash'],
  'JPN225': ['JPN225', 'NIKKEI', 'NI225', 'JP225', 'JPN225.cash'],
  'BTCUSD': ['BTCUSD', 'BTC', 'BITCOIN', 'BTC/USD', 'BTCUSDm', 'BTCUSD.std'],
  'ETHUSD': ['ETHUSD', 'ETH', 'ETHEREUM', 'ETH/USD', 'ETHUSDm'],
  'USOIL':  ['USOIL', 'WTI', 'CRUDE', 'CL', 'USOIL.cash', 'OILWTI'],
  'UKOIL':  ['UKOIL', 'BRENT', 'BRT', 'UKOIL.cash', 'OILBRENT']
};

// Retourne tous les noms candidats pour un symbole demandé
// FIX : on retourne aussi les variantes avec casse mixte (Gold, BtcUsd...) pour brokers qui s'en servent
function getSymbolCandidates(baseSymbol) {
  const sym = (baseSymbol || '').toUpperCase();
  // Trouver le groupe d'alias auquel appartient ce symbole
  for (const [canonical, aliases] of Object.entries(SYMBOL_ALIASES)) {
    if (aliases.some(a => a.toUpperCase() === sym)) {
      // On retourne les alias TELS QUELS (avec leur casse originale) + en majuscules
      // Ex: pour XAUUSD → ['XAUUSD', 'GOLD', 'Gold', 'XAU', ...]
      const all = new Set();
      aliases.forEach(a => {
        all.add(a);                    // casse originale (ex: 'Gold')
        all.add(a.toUpperCase());      // majuscules (ex: 'GOLD')
      });
      all.add(sym);
      return Array.from(all);
    }
  }
  // Pas dans la table → on garde le nom original
  return [sym];
}

// FIX : getHistoricalCandles n'existe pas sur RPCConnection selon la version SDK
// Ce helper essaie connection puis account, et retourne [] si rien ne marche
function tfToMs(tf) {
  const map = { '1m': 60000, '5m': 300000, '15m': 900000, '30m': 1800000, '1h': 3600000, '4h': 14400000, '1d': 86400000 };
  return map[tf] || 3600000;
}

async function getCandles(connection, account, symbol, timeframe, limit) {
  // FIX : getHistoricalCandles est sur le ACCOUNT (SDK metaapi recent)
  // Signature : account.getHistoricalCandles(symbol, timeframe, startTime, limit)
  const startTime = new Date(Date.now() - (limit + 10) * tfToMs(timeframe));

  // Methode 1 (prioritaire) : account.getHistoricalCandles
  if (account && typeof account.getHistoricalCandles === 'function') {
    try {
      const c = await account.getHistoricalCandles(symbol, timeframe, startTime, limit);
      if (Array.isArray(c) && c.length > 0) return c;
    } catch(e) { console.log('[getCandles] account: ' + e.message); }
  }
  // Methode 2 (ancien SDK) : connection.getHistoricalCandles
  if (connection && typeof connection.getHistoricalCandles === 'function') {
    try {
      const c = await connection.getHistoricalCandles(symbol, timeframe, startTime, limit);
      if (Array.isArray(c) && c.length > 0) return c;
    } catch(e) { console.log('[getCandles] connection: ' + e.message); }
  }
  return [];
}

async function resolveSymbolForUser(connection, baseSymbol, serverName) {
  // FIX : on garde aussi la casse originale pour les brokers qui ont "Gold" (RaiseFX par ex)
  const symRaw = (baseSymbol || '').trim();
  const sym = symRaw.toUpperCase();
  const sn = (serverName || '').toUpperCase();
  let suffixes;
  if (sn.includes('STD')) suffixes = ['-STD', '-VIP', '', '-ECN', '-PRO', '-Raw', '.a', '_m', '-micro', '.cash'];
  else if (sn.includes('VIP')) suffixes = ['-VIP', '-STD', '', '-ECN', '-PRO', '-Raw', '.a', '_m', '-micro', '.cash'];
  else if (sn.includes('ECN')) suffixes = ['-ECN', '', '-STD', '-VIP', '-PRO', '-Raw', '.a', '_m', '-micro', '.cash'];
  else suffixes = ['', '-VIP', '-STD', '-ECN', '-PRO', '-Raw', '.a', '_m', '-micro', '.cash', '.raw', '#', 'c', 'm', '.r', 'pro', '.pro', '.std', '_SB', 'x'];

  // 1. Essayer le symbole demandé avec ses suffixes serveur
  for (const sfx of suffixes) {
    try {
      const candidate = sym + sfx;
      const tick = await connection.getSymbolPrice(candidate);
      if (tick && tick.bid && tick.bid > 0 && tick.ask && tick.ask > 0) {
        return { symbol: candidate, bid: tick.bid, ask: tick.ask, mid: (tick.bid + tick.ask) / 2 };
      }
    } catch(e) {}
  }

  // 2. Si rien trouvé, essayer les alias multi-broker (ex: GOLD au lieu de XAUUSD)
  const candidates = getSymbolCandidates(sym);
  for (const cand of candidates) {
    if (cand === sym) continue; // déjà testé
    for (const sfx of suffixes) {
      try {
        const fullCandidate = cand + sfx;
        const tick = await connection.getSymbolPrice(fullCandidate);
        if (tick && tick.bid && tick.bid > 0 && tick.ask && tick.ask > 0) {
          console.log('[SYMBOL-RESOLVE] Alias trouvé : ' + sym + ' → ' + fullCandidate);
          return { symbol: fullCandidate, bid: tick.bid, ask: tick.ask, mid: (tick.bid + tick.ask) / 2 };
        }
      } catch(e) {}
    }
  }

  console.log('[SYMBOL-RESOLVE] Aucun match pour ' + sym + ' sur serveur ' + sn);
  return null;
}

// ═══ ANALYSE VOLUME (tick volume MetaApi) ═══
function detecterVolumeSpike(candles, ratio = 2.0, lookback = 20) {
  if (!candles || candles.length < lookback + 1) return null;
  const recent = candles.slice(-lookback - 1, -1);
  const last = candles[candles.length - 1];
  if (!last.tickVolume && !last.volume) return null;
  const lastVol = last.tickVolume || last.volume || 0;
  if (lastVol === 0) return null;
  const avgVol = recent.reduce((s, c) => s + (c.tickVolume || c.volume || 0), 0) / recent.length;
  if (avgVol === 0) return null;
  const ratioActuel = lastVol / avgVol;
  return { spike: ratioActuel >= ratio, ratio: +ratioActuel.toFixed(2), lastVol, avgVol: +avgVol.toFixed(0) };
}

function calculerPOC(candles, nBins = 20) {
  if (!candles || candles.length < 10) return null;
  let minP = Infinity, maxP = -Infinity;
  for (const c of candles) {
    if (c.low < minP) minP = c.low;
    if (c.high > maxP) maxP = c.high;
  }
  if (maxP === minP) return null;
  const binSize = (maxP - minP) / nBins;
  const bins = new Array(nBins).fill(0);
  for (const c of candles) {
    const vol = c.tickVolume || c.volume || 1;
    const startBin = Math.max(0, Math.floor((c.low - minP) / binSize));
    const endBin = Math.min(nBins - 1, Math.floor((c.high - minP) / binSize));
    const nBinsTouches = Math.max(1, endBin - startBin + 1);
    const volParBin = vol / nBinsTouches;
    for (let i = startBin; i <= endBin; i++) bins[i] += volParBin;
  }
  let maxBinIdx = 0, maxBinVol = 0;
  for (let i = 0; i < nBins; i++) {
    if (bins[i] > maxBinVol) { maxBinVol = bins[i]; maxBinIdx = i; }
  }
  const poc = minP + (maxBinIdx + 0.5) * binSize;
  return { poc: +poc.toFixed(2), range: { min: +minP.toFixed(2), max: +maxP.toFixed(2) } };
}

function detecterDivergenceVolume(candles, lookback = 10) {
  if (!candles || candles.length < lookback + 5) return null;
  const recent = candles.slice(-lookback);
  const moitie = Math.floor(lookback / 2);
  const p1 = recent.slice(0, moitie);
  const p2 = recent.slice(moitie);
  const max1 = Math.max(...p1.map(c => c.high));
  const max2 = Math.max(...p2.map(c => c.high));
  const min1 = Math.min(...p1.map(c => c.low));
  const min2 = Math.min(...p2.map(c => c.low));
  const vol1 = p1.reduce((s, c) => s + (c.tickVolume || c.volume || 0), 0) / p1.length;
  const vol2 = p2.reduce((s, c) => s + (c.tickVolume || c.volume || 0), 0) / p2.length;
  if (vol1 === 0 || vol2 === 0) return null;
  if (max2 > max1 && vol2 < vol1 * 0.85) return { type: 'BEARISH_DIVERGENCE', message: 'Essoufflement haussier' };
  if (min2 < min1 && vol2 < vol1 * 0.85) return { type: 'BULLISH_DIVERGENCE', message: 'Essoufflement baissier' };
  return { type: 'NONE' };
}

// ═══ CALCUL TPs INTELLIGENTS BASES SUR NIVEAUX MARCHE REELS ═══
function calculerTPsIntelligents(direction, entree, sl, analyseICT, pocData) {
  if (!entree || !sl) return null;
  const isBuy = direction === 'BUY';
  const distSL = Math.abs(entree - sl);
  if (distSL <= 0) return null;
  const candidats = [];
  const addCandidat = (prix, source) => {
    if (!prix || isNaN(prix) || prix <= 0) return;
    const distance = Math.abs(prix - entree);
    if (isBuy && prix <= entree) return;
    if (!isBuy && prix >= entree) return;
    if (distance < distSL * 0.8) return;
    const rr = distance / distSL;
    candidats.push({ prix: +prix.toFixed(5), source, rr: +rr.toFixed(2), distance });
  };
  if (analyseICT && analyseICT.fibonacci && analyseICT.fibonacci.niveaux) {
    addCandidat(analyseICT.fibonacci.niveaux['127.2'], 'Fibo 127.2%');
    addCandidat(analyseICT.fibonacci.niveaux['161.8'], 'Fibo 161.8%');
  }
  if (analyseICT && analyseICT.fibonacciH1 && analyseICT.fibonacciH1.niveaux) {
    addCandidat(analyseICT.fibonacciH1.niveaux['127.2'], 'Fibo H1 127.2%');
    addCandidat(analyseICT.fibonacciH1.niveaux['161.8'], 'Fibo H1 161.8%');
  }
  if (analyseICT && analyseICT.drawOnLiquidity && analyseICT.drawOnLiquidity.toutes) {
    analyseICT.drawOnLiquidity.toutes.forEach(c => {
      if ((isBuy && c.side === 'BULLISH') || (!isBuy && c.side === 'BEARISH')) addCandidat(c.price, 'DOL ' + c.type);
    });
  }
  if (analyseICT && analyseICT.asianRange) {
    if (isBuy) addCandidat(analyseICT.asianRange.high, 'Asian High');
    else addCandidat(analyseICT.asianRange.low, 'Asian Low');
  }
  if (analyseICT && analyseICT.dealingRange) {
    if (isBuy) addCandidat(analyseICT.dealingRange.high, 'Dealing Range High');
    else addCandidat(analyseICT.dealingRange.low, 'Dealing Range Low');
  }
  if (pocData && pocData.poc) addCandidat(pocData.poc, 'POC');
  if (analyseICT && analyseICT.liquidite) {
    if (isBuy && analyseICT.liquidite.equalHighs) analyseICT.liquidite.equalHighs.forEach(e => addCandidat(e.price, 'Equal Highs'));
    if (!isBuy && analyseICT.liquidite.equalLows) analyseICT.liquidite.equalLows.forEach(e => addCandidat(e.price, 'Equal Lows'));
  }
  if (candidats.length === 0) return null;
  candidats.sort((a, b) => a.distance - b.distance);
  const dedupes = [];
  for (const c of candidats) {
    const trouve = dedupes.find(d => Math.abs(d.prix - c.prix) < distSL * 0.3);
    if (!trouve) dedupes.push(c);
  }
  let tp1 = dedupes.find(c => c.rr >= 1.0 && c.rr <= 3.0) || dedupes[0];
  let tp2 = dedupes.find(c => c !== tp1 && c.rr > (tp1?.rr || 1.5) && c.rr >= 2.5 && c.rr <= 5.5);
  const srcMaj = ['DOL', 'Asian', 'Fibo H1 161', 'Fibo 161', 'Dealing Range'];
  let tp3 = dedupes.find(c => c !== tp1 && c !== tp2 && c.rr >= 4.0 && srcMaj.some(s => c.source.includes(s)));
  if (!tp3) tp3 = dedupes.find(c => c !== tp1 && c !== tp2 && c.rr > (tp2?.rr || 3));
  return {
    tp1: tp1?.prix, tp1Source: tp1?.source, tp1RR: tp1?.rr,
    tp2: tp2?.prix, tp2Source: tp2?.source, tp2RR: tp2?.rr,
    tp3: tp3?.prix, tp3Source: tp3?.source, tp3RR: tp3?.rr
  };
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

// ═══ DOSSIER DE DONNÉES PERSISTANT (DBs survivent aux redéploys Render) ═══
// Si Render a un disk monté sur /data → on l'utilise (utilisateurs ne disparaissent plus).
// Sinon fallback sur le dossier projet (pour dev local).
// IMPORTANT : sur Render, va dans Disks → Add Disk → mount path /data → 1 GB gratuit
const DATA_DIR = process.env.DATA_DIR || (fs.existsSync('/data') ? '/data' : __dirname);
try { if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true }); } catch(e) {}
console.log('[DB] Stockage persistant : ' + DATA_DIR);

const db = new Datastore({ filename: path.join(DATA_DIR, 'users.db'), autoload: true });
const analysesDb = new Datastore({ filename: path.join(DATA_DIR, 'analyses.db'), autoload: true });
const leconsDb = new Datastore({ filename: path.join(DATA_DIR, 'lecons.db'), autoload: true });
const setupsGagnantsDb = new Datastore({ filename: path.join(DATA_DIR, 'setups-gagnants.db'), autoload: true });
const positionsTrackingDb = new Datastore({ filename: path.join(DATA_DIR, 'positions-tracking.db'), autoload: true });
const notificationsDb = new Datastore({ filename: path.join(DATA_DIR, 'notifications.db'), autoload: true });
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

// ═══════════════════════════════════════════════════════════════════
// 🔒 GATING PRO/ELITE — accès aux fonctionnalités avancées
// ═══════════════════════════════════════════════════════════════════
// Plans : free | starter | premium (= "pro") | elite
// Les plans "premium" et "elite" ont accès à :
//   - Connexion MT5 + ordres auto
//   - Apprentissage IA personnalisé (post-mortem, setups gagnants)
//   - Alertes A+ par email + notif in-app
//   - Cours / contenus premium
//   - Réajustement automatique entrée (anti-piège)

function hasPremiumAccess(user) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  if (!user.subscribed) return false;
  // Bug fix : si le paiement est en retard, plus d'accès Premium
  if (typeof isPaiementEnRetard === 'function' && isPaiementEnRetard(user)) return false;
  // Seuls 'premium' (= pro) et 'elite' ont l'accès complet
  return user.plan === 'premium' || user.plan === 'elite' || user.plan === 'pro';
}

// Middleware : bloque la route si l'utilisateur n'a pas le bon plan
async function checkPremium(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  try {
    const user = await db.findOneAsync({ _id: req.session.userId });
    if (!hasPremiumAccess(user)) {
      return res.status(403).json({
        error: 'mt5_plan_required',
        message: '🔒 Connexion MT5 réservée aux plans Pro et Elite. Contacte @bigtazz pour upgrader.',
        requiresPlan: 'premium',
        currentPlan: user?.plan || 'free'
      });
    }
    req.user = user;
    next();
  } catch(e) { res.status(500).json({ error: e.message }); }
}

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


// ─── Middleware restriction plan Premium/Elite ──────────────────────
function checkPremiumPlan(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  db.findOneAsync({ _id: req.session.userId }).then(user => {
    if (!user) return res.status(401).json({ error: 'Utilisateur non trouvé' });
    if (user.role === 'admin') return next();
    if (hasPremiumAccess(user)) return next();
    return res.status(403).json({ error: 'plan_required', message: 'Réservé aux plans Premium et Elite.' });
  }).catch(() => res.status(500).json({ error: 'Erreur serveur' }));
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
  } else if (inst.includes('BTC') || inst.includes('BITCOIN')) {
    // BTC : 1 lot = 1 BTC. 1$ de mouvement = 1$ par lot
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0 ? slDistanceDollars : slPips;
    valeurMouvementParLot = 1;
  } else if (inst.includes('ETH') || inst.includes('ETHEREUM')) {
    // ETH : 1 lot = 1 ETH typically. 1$ = 1$ par lot
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0 ? slDistanceDollars : slPips;
    valeurMouvementParLot = 1;
  } else if (inst.includes('JPY')) {
    // Forex JPY : 1 pip = 0.01, 1 lot = ~$9 par pip
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0
      ? slDistanceDollars
      : slPips * 0.01;
    valeurMouvementParLot = 909; // ~$9.09 par pip * 100 pips/dollar
  } else if (inst.includes('NAS') || inst.includes('NDX') || inst.includes('US100')) {
    // NAS100 : 1 lot = 1 contract. 1 point = 1$ par lot
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0 ? slDistanceDollars : slPips;
    valeurMouvementParLot = 1;
  } else if (inst.includes('SPX') || inst.includes('SP500') || inst.includes('US500')) {
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0 ? slDistanceDollars : slPips;
    valeurMouvementParLot = 1;
  } else if (inst.includes('US30') || inst.includes('DOW') || inst.includes('DJI')) {
    // US30 : 1 lot = 1 contract Dow, 1 point = 1$ par lot (typique broker FX)
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0 ? slDistanceDollars : slPips;
    valeurMouvementParLot = 1;
  } else if (inst.includes('GER40') || inst.includes('DAX') || inst.includes('GER30')) {
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0 ? slDistanceDollars : slPips;
    valeurMouvementParLot = 1;
  } else if (inst.includes('OIL') || inst.includes('USOIL') || inst.includes('WTI') || inst.includes('UKOIL') || inst.includes('BRENT')) {
    // Oil : 1 lot = 1000 barils, 1$ de mouvement = 1000$ par lot
    slEnDollars = slDistanceDollars !== null && slDistanceDollars > 0 ? slDistanceDollars : slPips;
    valeurMouvementParLot = 1000;
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
  // Pour XAUUSD ET autres actifs : si lot trop petit, pas de profit utile
  let lotMinimum;
  if (inst.includes('XAU') || inst.includes('GOLD')) {
    if (capital < 300) lotMinimum = 0.01;
    else if (capital < 1000) lotMinimum = 0.02;
    else if (capital < 3000) lotMinimum = 0.03;
    else lotMinimum = 0.05;
  } else if (inst.includes('BTC') || inst.includes('ETH')) {
    // Crypto : lot très petit possible (0.01 BTC = $1000+ valeur exposition)
    lotMinimum = 0.01;
  } else if (inst.includes('NAS') || inst.includes('US100') || inst.includes('SPX') || inst.includes('US500') || inst.includes('US30') || inst.includes('GER40')) {
    // Indices : 0.10 lot minimum utile
    if (capital < 500) lotMinimum = 0.10;
    else if (capital < 2000) lotMinimum = 0.20;
    else lotMinimum = 0.50;
  } else if (inst.includes('OIL') || inst.includes('WTI') || inst.includes('BRENT')) {
    lotMinimum = 0.01; // Oil très volatil
  } else {
    // Forex standard : 0.01 par défaut sur petit compte
    if (capital < 500) lotMinimum = 0.01;
    else if (capital < 2000) lotMinimum = 0.05;
    else lotMinimum = 0.10;
  }
  if (lots < lotMinimum) {
    console.log('[LOTS] Calcul: ' + lots + ' → ajuste a ' + lotMinimum + ' (capital $' + capital + ', ' + inst + ')');
    lots = lotMinimum;
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
// ─── RSI WILDER (lissage exponentiel — méthode officielle Wilder 1978) ──────
// Besoin de 2×période bougies minimum pour la phase de chauffe.
// Phase 1 (chauffe) : moyenne simple sur les 'periode' premières variations.
// Phase 2 (lissage) : avgGain = (prevAvgGain × (n-1) + gain) / n — comme TradingView.
// Différence vs simple : ±3-5 points sur les extrêmes → alertes RSI plus fiables.
function calculerRSI(candles, periode = 14) {
  // Besoin : au moins 2×periode + 1 bougies pour lissage correct
  const minBougies = periode * 2 + 1;
  if (!candles || candles.length < minBougies) {
    // Fallback : méthode simple si pas assez de bougies (rares cas)
    if (!candles || candles.length < periode + 1) return null;
    const closesSimple = candles.slice(-(periode + 1)).map(c => c.close);
    let g = 0, p = 0;
    for (let i = 1; i < closesSimple.length; i++) {
      const d = closesSimple[i] - closesSimple[i - 1];
      if (d > 0) g += d; else p += Math.abs(d);
    }
    if (p === 0) return 100;
    if (g === 0) return 0;
    return +(100 - (100 / (1 + (g / periode) / (p / periode)))).toFixed(1);
  }

  const closes = candles.slice(-(minBougies)).map(c => c.close);

  // Phase 1 : moyenne simple sur les 'periode' premières variations (chauffe)
  let avgGain = 0, avgLoss = 0;
  for (let i = 1; i <= periode; i++) {
    const diff = closes[i] - closes[i - 1];
    if (diff > 0) avgGain += diff;
    else avgLoss += Math.abs(diff);
  }
  avgGain /= periode;
  avgLoss /= periode;

  // Phase 2 : lissage Wilder sur les bougies restantes
  for (let i = periode + 1; i < closes.length; i++) {
    const diff = closes[i] - closes[i - 1];
    const gain = diff > 0 ? diff : 0;
    const loss = diff < 0 ? Math.abs(diff) : 0;
    avgGain = (avgGain * (periode - 1) + gain) / periode;
    avgLoss = (avgLoss * (periode - 1) + loss) / periode;
  }

  if (avgLoss === 0) return 100;
  if (avgGain === 0) return 0;
  const rs = avgGain / avgLoss;
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

// ─── ADX WILDER (lissage exponentiel — méthode officielle Wilder 1978) ──────
// Phase 1 (chauffe) : somme brute des TR/DM sur 'periode' barres.
// Phase 2 (lissage) : smoothedTR = prevTR - (prevTR / n) + currentTR (Wilder).
// Besoin : au moins 2×periode + 1 bougies (comme TradingView).
// Différence vs simple : ADX moins erratique, valeurs DX plus stables.
function calculerADX(candles, periode = 14) {
  const minBougies = periode * 2 + 1;
  if (!candles || candles.length < minBougies) {
    // Fallback méthode simple si pas assez de bougies
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

  const slice = candles.slice(-minBougies);

  // Phase 1 : chauffe — somme brute sur la première 'periode' barres
  let smoothedTR = 0, smoothedDMPlus = 0, smoothedDMMinus = 0;
  const dxHistory = [];

  for (let i = 1; i <= periode; i++) {
    const c = slice[i], p = slice[i - 1];
    const tr = Math.max(c.high - c.low, Math.abs(c.high - p.close), Math.abs(c.low - p.close));
    const upMove = c.high - p.high;
    const downMove = p.low - c.low;
    smoothedTR += tr;
    smoothedDMPlus += (upMove > downMove && upMove > 0) ? upMove : 0;
    smoothedDMMinus += (downMove > upMove && downMove > 0) ? downMove : 0;
  }

  // Phase 2 : lissage Wilder sur les barres suivantes
  for (let i = periode + 1; i < slice.length; i++) {
    const c = slice[i], p = slice[i - 1];
    const tr = Math.max(c.high - c.low, Math.abs(c.high - p.close), Math.abs(c.low - p.close));
    const upMove = c.high - p.high;
    const downMove = p.low - c.low;
    const dmPlus = (upMove > downMove && upMove > 0) ? upMove : 0;
    const dmMinus = (downMove > upMove && downMove > 0) ? downMove : 0;

    // Lissage Wilder : smoothed = prev - (prev / n) + current
    smoothedTR = smoothedTR - (smoothedTR / periode) + tr;
    smoothedDMPlus = smoothedDMPlus - (smoothedDMPlus / periode) + dmPlus;
    smoothedDMMinus = smoothedDMMinus - (smoothedDMMinus / periode) + dmMinus;

    if (smoothedTR === 0) continue;
    const diPlus = (smoothedDMPlus / smoothedTR) * 100;
    const diMinus = (smoothedDMMinus / smoothedTR) * 100;
    const dx = (Math.abs(diPlus - diMinus) / (diPlus + diMinus || 1)) * 100;
    dxHistory.push({ dx, diPlus, diMinus });
  }

  if (!dxHistory.length) return null;

  // ADX = moyenne lissée des DX sur 'periode' dernières valeurs
  const recentDX = dxHistory.slice(-periode);
  const adx = recentDX.reduce((s, d) => s + d.dx, 0) / recentDX.length;
  const last = dxHistory[dxHistory.length - 1];

  return { adx: +adx.toFixed(1), diPlus: +last.diPlus.toFixed(1), diMinus: +last.diMinus.toFixed(1) };
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

  // ─── M6 : MOUVEMENT VIOLENT RÉCENT (capture les crashes/pumps explosifs) ─
  // FIX BUG : sur ta capture H1 du 15/05, le marché chutait de 4759 → 4648
  // (-2.3%) en ~6 bougies mais les autres méthodes ne détectaient que "RANGE"
  // car la chute était trop récente pour faire bouger MA50/ADX/swings structurels.
  // Cette méthode CAPTURE explicitement ces moves explosifs.
  try {
    const dernieres8 = candles.slice(-8);
    const dernieres12 = candles.slice(-12);
    if (dernieres8.length >= 8 && dernieres12.length >= 12) {
      // Mouvement net sur 8 bougies : open de la 1ère vs close de la dernière
      const moveRecent = dernieres8[dernieres8.length-1].close - dernieres8[0].open;
      const movePct = Math.abs(moveRecent) / dernieres8[0].open * 100;

      // Bougies majoritairement du même côté (5+ sur 8)
      let bullRecent = 0, bearRecent = 0;
      dernieres8.forEach(c => { if (c.close > c.open) bullRecent++; else if (c.close < c.open) bearRecent++; });

      // Calcul de l'ATR (Average True Range) pour calibrer
      let atrSum = 0;
      dernieres12.forEach(c => atrSum += (c.high - c.low));
      const atrAvg = atrSum / dernieres12.length;

      // Mouvement violent = mouvement total > 3× ATR moyen sur 8 bougies
      const moveViolent = Math.abs(moveRecent) > atrAvg * 3;

      debug.method6 = {
        moveRecent: +moveRecent.toFixed(2),
        movePct: +movePct.toFixed(2),
        bullRecent, bearRecent,
        atrAvg: +atrAvg.toFixed(2),
        moveViolent
      };

      // Vote BEAR si chute violente + majorité bougies rouges
      if (moveRecent < 0 && moveViolent && bearRecent >= 5) {
        votesBearish++;
        votes.m6 = 'BEAR';
      }
      // Vote BULL si montée violente + majorité bougies vertes
      else if (moveRecent > 0 && moveViolent && bullRecent >= 5) {
        votesBullish++;
        votes.m6 = 'BULL';
      }
      else votes.m6 = 'NEUTRAL';
    }
  } catch(e) { debug.method6 = { error: e.message }; votes.m6 = 'NEUTRAL'; }

  // ─── DÉCISION FINALE ─────────────────────────────────────────────
  // Si choppy ET pas de majorité écrasante → RANGE forcé
  let trend = 'RANGE';
  let confidence = 0;
  // FIX : on a maintenant 6 méthodes (M1 à M6). Sur 6, on garde le seuil à 3+
  // mais la confidence max est 6/6. Pour rester compatible avec les checks
  // "confidence >= 4" existants, on continue à compter sur l'échelle 5.
  if (votesBullish >= 3 && votesBullish > votesBearish && (!isChoppy || votesBullish >= 4)) {
    trend = 'BULLISH';
    // Normaliser sur 5 (6→5, 5→5, 4→4, 3→3) pour rester compatible
    confidence = Math.min(votesBullish, 5);
  } else if (votesBearish >= 3 && votesBearish > votesBullish && (!isChoppy || votesBearish >= 4)) {
    trend = 'BEARISH';
    confidence = Math.min(votesBearish, 5);
  } else {
    confidence = Math.min(Math.max(votesBullish, votesBearish), 5);
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

// ═══════════════════════════════════════════════════════════════════
// 📐 FIBONACCI AUTOMATIQUE — niveaux clés sur le swing en cours
// ═══════════════════════════════════════════════════════════════════
// Détecte le DERNIER swing high + DERNIER swing low majeurs, calcule :
//   - Niveaux de retracement : 23.6/38.2/50/61.8/78.6/100
//   - Extensions (TP) : 127.2/161.8
//   - Zone OTE (Optimal Trade Entry = 61.8% à 78.6%) — clé en ICT
//
// FILTRES anti-faux Fibo (3 conditions) :
//   1. Amplitude ≥ 5× ATR (sinon swing trop petit = noise)
//   2. ≥ 3 bougies entre les 2 swings (anti-pseudo-swing)
//   3. ≤ 50 bougies depuis le swing (sinon obsolète)
//
// Retourne null si pas de swing valide.
function calculerFibonacci(candles, lookback = 5) {
  if (!candles || candles.length < 30) return null;
  const swings = detecterSwings(candles, lookback);
  if (!swings.highs.length || !swings.lows.length) return null;

  const lastHigh = swings.highs[swings.highs.length - 1];
  const lastLow  = swings.lows[swings.lows.length - 1];

  // FILTRE 1 : amplitude min 5× ATR
  const atr = calculerATR(candles, 14);
  const amplitude = Math.abs(lastHigh.price - lastLow.price);
  if (atr > 0 && amplitude < atr * 5) return null;

  // FILTRE 2 : ≥ 3 bougies entre les swings
  if (Math.abs(lastHigh.index - lastLow.index) < 3) return null;

  // FILTRE 3 : swing pas trop ancien
  const dernierIndex = candles.length - 1;
  const swingPlusRecent = Math.max(lastHigh.index, lastLow.index);
  if (dernierIndex - swingPlusRecent > 50) return null;

  // Sens : lastHigh + récent que lastLow → swing UP
  const sens = lastHigh.index > lastLow.index ? 'UP' : 'DOWN';
  const debut = sens === 'UP' ? lastLow.price : lastHigh.price;
  const fin   = sens === 'UP' ? lastHigh.price : lastLow.price;
  const range = fin - debut;

  const niveaux = {
    '0': debut,
    '23.6': debut + range * 0.236,
    '38.2': debut + range * 0.382,
    '50': debut + range * 0.5,
    '61.8': debut + range * 0.618,
    '78.6': debut + range * 0.786,
    '100': fin,
    '127.2': debut + range * 1.272,
    '161.8': debut + range * 1.618
  };
  for (const k of Object.keys(niveaux)) niveaux[k] = +niveaux[k].toFixed(2);

  // Zone OTE 61.8% — 78.6%
  const oteZone = {
    debut: niveaux['61.8'],
    fin: niveaux['78.6'],
    type: sens === 'UP' ? 'BUY' : 'SELL'
  };

  const prixActuel = candles[candles.length - 1].close;
  let pctRetrace = null;
  if (range !== 0) pctRetrace = +(((prixActuel - debut) / range) * 100).toFixed(1);

  // Détecter si prix dans OTE — fix bug : normaliser min/max (en SELL la zone s'inverse)
  const oteMin = Math.min(oteZone.debut, oteZone.fin);
  const oteMax = Math.max(oteZone.debut, oteZone.fin);
  const dansOTE = prixActuel >= oteMin && prixActuel <= oteMax;

  return {
    sens,
    swingHigh: +lastHigh.price.toFixed(2),
    swingLow: +lastLow.price.toFixed(2),
    amplitude: +amplitude.toFixed(2),
    niveaux,
    oteZone,
    prixActuel: +prixActuel.toFixed(2),
    pctRetrace,
    dansOTE,
    bougiesDepuisSwing: dernierIndex - swingPlusRecent
  };
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
  // ─── FIBONACCI : sur le dernier swing M15 + H1 (confluence) ───
  const fibonacci    = calculerFibonacci(candlesM15, 5);
  const fibonacciH1  = candlesH1 ? calculerFibonacci(candlesH1, 5) : null;

  return {
    structureM15,
    structureH1,
    dealingRange,
    liquidite,
    asianRange,
    drawOnLiquidity: dol,
    killZone,
    atr,
    fibonacci,
    fibonacciH1,
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

  // ═══ FIBONACCI sur le swing en cours (M15) ═══
  if (analyse.fibonacci) {
    const fib = analyse.fibonacci;
    txt += `\n📐 FIBONACCI M15 (swing ${fib.sens}) :\n`;
    txt += `  - Swing high: ${fib.swingHigh} | Swing low: ${fib.swingLow} | Amplitude: ${fib.amplitude}\n`;
    txt += `  - Niveaux : 38.2%=${fib.niveaux['38.2']} | 50%=${fib.niveaux['50']} | 61.8%=${fib.niveaux['61.8']} | 78.6%=${fib.niveaux['78.6']}\n`;
    txt += `  - Extensions : 127.2%=${fib.niveaux['127.2']} | 161.8%=${fib.niveaux['161.8']}\n`;
    txt += `  - Prix actuel: ${fib.prixActuel} (retracement ${fib.pctRetrace}%)\n`;
    if (fib.dansOTE) {
      txt += `  - 🎯 PRIX DANS LA ZONE OTE (Optimal Trade Entry 61.8%-78.6%) → setup ${fib.oteZone.type} prioritaire\n`;
    } else if (fib.pctRetrace !== null && fib.pctRetrace < 38.2 && fib.sens === 'UP') {
      txt += `  - ⚠️ Prix peu retracé (< 38.2%) → attendre un retracement plus profond avant d'entrer en BUY\n`;
    } else if (fib.pctRetrace !== null && fib.pctRetrace > 78.6 && fib.sens === 'UP') {
      txt += `  - ⚠️ Prix retracé > 78.6% → swing potentiellement invalidé, prudence\n`;
    }
    txt += `  - 💡 USAGE : place tes TPs sur extensions (127.2% / 161.8%) ou sur swing high/low (100%)\n`;
  }

  // FIBO H1 : confluence forte si prix dans OTE H1 ET M15
  if (analyse.fibonacciH1 && analyse.fibonacciH1.dansOTE) {
    txt += `\n🔥 CONFLUENCE FIBO H1 : prix dans OTE H1 (${analyse.fibonacciH1.niveaux['61.8']} - ${analyse.fibonacciH1.niveaux['78.6']}) → ${analyse.fibonacciH1.oteZone.type} très haute probabilité\n`;
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
  // Distribution OPTIMISÉE :
  // - Setup A+ (9-10) : 40/30/30 — RR 1:2 / 1:4 / 1:8 (jackpot avec 30% en runner)
  // - Setup A (7-8) : 50/50 — comme demandé, sécurité maximale (tp1 et tp2 = chacun 50%)
  // - Setup B (rare avec score min 7) : 100% à TP1
  // Avec la sécurité TP partiel : SL → BE après TP1 (chaque trade sécurisé)
  if (score >= 9)      return { tp1: 0.40, tp2: 0.30, tp3: 0.30, mode: 'A_PLUS' };
  if (score >= 7)      return { tp1: 0.50, tp2: 0.50, tp3: 0,    mode: 'A' }; // 50% TP1 + 50% TP2 (demande Leon)
  if (score >= 6)      return { tp1: 0.70, tp2: 0.30, tp3: 0,    mode: 'B' };
  return                      { tp1: 1.00, tp2: 0,    tp3: 0,    mode: 'C' };
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

    // ─── FIX COÛT METAAPI : filtre préventif avant de deploy ────────────
    // On ne deploie un compte que si l'utilisateur a au moins 1 analyse BUY/SELL
    // des dernières 24h. Évite de deploy les comptes inactifs inutilement.
    const il_y_a_24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const userIdsActifs = new Set();
    try {
      const analysesActives = await analysesDb.findAsync({
        decision: { $in: ['BUY', 'SELL'] },
        createdAt: { $gte: il_y_a_24h }
      });
      for (const a of analysesActives) { if (a.userId) userIdsActifs.add(a.userId); }
    } catch(e) { console.log('[TP-WRAPPER] Erreur filtre actifs:', e.message); }

    const now = Date.now();
    for (const user of users) {
      // Skip si on a déjà checké ce user dans les 2 dernières minutes
      const lastCheck = _wrapperCheckCache.get(user._id);
      if (lastCheck && (now - lastCheck) < WRAPPER_MIN_INTERVAL_MS) {
        continue;
      }
      // FIX ÉCO : skip si erreur récente sur ce compte (cooldown 5 min)
      const lastError = _wrapperErrorCache.get(user._id);
      if (lastError && (now - lastError) < ERROR_COOLDOWN_MS) {
        continue;
      }
      _wrapperCheckCache.set(user._id, now);
      // Nettoyer le cache des entrées trop anciennes (>10 min)
      if (_wrapperCheckCache.size > 50) {
        for (const [k, v] of _wrapperCheckCache.entries()) {
          if (now - v > 10 * 60 * 1000) _wrapperCheckCache.delete(k);
        }
      }
      let deployedHere = false;
      let account = null;
      try {
        // ─── FIX COÛT : skip les users sans analyse récente ────────────
        // S'il n'a aucune analyse BUY/SELL dans les 24h → impossible d'avoir
        // une position ouverte à gérer → on évite un deploy inutile.
        if (!userIdsActifs.has(user._id)) continue;

        // ─── FIX FUITE METAAPI : ne deploy QUE si quelque chose à gérer ─
        // Avant de deploy le compte (= cher), on vérifie 2 conditions :
        //   1. Y a-t-il un tracking actif en DB locale (= position déjà notée)
        //   2. OU y a-t-il une analyse < 7 jours avec orderPlaced=true et pas
        //      encore traitée par l'apprentissage (= ordre encore actif)
        // Si NI l'un NI l'autre → skip (pas de position à gérer)
        const trackingsActifs = await positionsTrackingDb.findAsync({
          userId: user._id,
          tp3Done: { $ne: true }
        });

        const il_y_a_7j = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        const il_y_a_24h_filt = new Date(Date.now() - 24 * 60 * 60 * 1000);

        // Ordres placés via "Ordre auto" (workflow normal)
        const ordresPlaces = await analysesDb.findAsync({
          userId: user._id,
          decision: { $in: ['BUY', 'SELL'] },
          orderPlaced: true,
          createdAt: { $gte: il_y_a_7j },
          apprentissageStatut: { $ne: 'TRAITE' }
        });

        // FIX : aussi les analyses récentes avec TP1/TP2/TP3 même SANS orderPlaced
        // (cas où le user a fait une analyse puis placé manuellement sur MT5)
        const analysesAvecTPs = await analysesDb.findAsync({
          userId: user._id,
          decision: { $in: ['BUY', 'SELL'] },
          createdAt: { $gte: il_y_a_24h_filt },
          $or: [{ tp1: { $exists: true } }, { tp: { $exists: true } }]
        });
        const aAnalyseAvecTPRecente = analysesAvecTPs && analysesAvecTPs.length > 0;

        const aQuelqueChoseAGerer = (trackingsActifs && trackingsActifs.length > 0) ||
                                    (ordresPlaces && ordresPlaces.length > 0) ||
                                    aAnalyseAvecTPRecente;

        if (!aQuelqueChoseAGerer) {
          // Aucun ordre + aucune analyse récente avec TPs → skip pour économiser MetaApi
          continue;
        }
        if (aAnalyseAvecTPRecente && !(trackingsActifs?.length || ordresPlaces?.length)) {
          // Cas du trade manuel : log pour debug
          console.log('[TP-WRAPPER] User ' + user._id + ' : analyse récente avec TPs détectée, on check les positions MT5 (trade manuel possible)');
        }

        account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);

        // ─── FIX : Auto-deploy temporaire si UNDEPLOYED ─────────────
        // Le wrapper TP DOIT pouvoir tourner même si le compte est undeployed,
        // sinon on rate les TP partiels après le timeout du watchdog.
        if (account.state !== 'DEPLOYED') {
          try {
            await account.deploy();
            if (typeof trackDeploy === 'function') trackDeploy(account.id, user.mt5.login);
            deployedHere = true;
            // FIX TIMEOUT : waitConnected avec limite 30s pour éviter les hangs
            await Promise.race([
              account.waitConnected(),
              new Promise((_, reject) => setTimeout(() => reject(new Error('waitConnected timeout 30s')), 30000))
            ]);
          } catch(deployErr) {
            console.log('[TP-WRAPPER] Deploy auto échoué pour ' + user._id + ': ' + deployErr.message);
            // FIX ÉCO : undeploy en cas d'échec pour pas laisser le compte facturé
            if (deployedHere) {
              try { await account.undeploy(); if (typeof trackUndeploy === 'function') trackUndeploy(account.id); } catch(e) {}
            }
            continue;
          }
        }

        const connection = account.getRPCConnection();
        // FIX TIMEOUT : connect + sync avec limite 30s
        try {
          await Promise.race([
            (async () => { await connection.connect(); await connection.waitSynchronized(); })(),
            new Promise((_, reject) => setTimeout(() => reject(new Error('sync timeout 30s')), 30000))
          ]);
        } catch(syncErr) {
          console.log('[TP-WRAPPER] Sync timeout user ' + user._id + ': ' + syncErr.message);
          // FIX ÉCO : marquer cet user en cooldown 5 min
          _wrapperErrorCache.set(user._id, Date.now());
          // Undeploy si on a déployé ici (pas la peine de garder un compte non sync)
          if (deployedHere) {
            try { await account.undeploy(); if (typeof trackUndeploy === 'function') trackUndeploy(account.id); } catch(e) {}
          }
          continue;
        }

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
            // FIX : chercher par positionId OU orderId (un tracking immédiat est créé avec orderId
            //        qui est ensuite égal au positionId pour market, mais peut différer pour limit déclenché)
            let tracking = await positionsTrackingDb.findOneAsync({ positionId: pos.id });
            if (!tracking) {
              // Fallback : matcher par orderId (cas où limit s'est exécuté avec positionId différent)
              tracking = await positionsTrackingDb.findOneAsync({ orderId: pos.id });
              if (!tracking) {
                // Fallback 2 : par symbole + direction + entrée proche (cas trade manuel)
                const positionEntry = parseFloat(pos.openPrice);
                const tradesProches = await positionsTrackingDb.findAsync({
                  userId: user._id,
                  symbol: { $regex: pos.symbol.split('-')[0] }, // match XAUUSD-STD → XAUUSD
                  direction: (pos.type === 'POSITION_TYPE_BUY') ? 'BUY' : 'SELL',
                  tp3Done: { $ne: true }
                });
                tracking = tradesProches.find(t => {
                  const entreeT = parseFloat(t.entree || t.entry || 0);
                  return Math.abs(entreeT - positionEntry) < (positionEntry * 0.003); // 0.3% tolérance
                });
              }
              // Si trouvé via fallback, on synchronise positionId pour la prochaine fois
              if (tracking) {
                await positionsTrackingDb.updateAsync(
                  { _id: tracking._id },
                  { $set: { positionId: pos.id } }
                );
                console.log('[WRAPPER-TP] Tracking ' + tracking._id + ' synchronisé avec positionId ' + pos.id);
              }
            }

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

            // ═══ PALIER 0a : MI-CHEMIN TP1 → SL avance à mi-risque (sécurise 50%) ═══
            // On ne ferme RIEN, on bouge juste le SL pour réduire le risque de moitié
            // Effet : à mi-chemin TP1, ton risque passe de 1R à 0.5R automatiquement
            if (!tracking.tp1Done && !tracking.miTp1Done) {
              const miTp1 = entree + (tp1 - entree) * 0.5; // milieu entre entrée et TP1
              const miTp1Atteint = isBuy ? prixActuel >= miTp1 : prixActuel <= miTp1;
              if (miTp1Atteint && tp1 > 0) {
                // SL → mi-chemin entre entrée et SL actuel (sécurise 50% du risque)
                const slMiRisque = isBuy
                  ? entree - (entree - sl) * 0.5  // BUY : SL plus haut (moins de risque)
                  : entree + (sl - entree) * 0.5; // SELL : SL plus bas
                try {
                  await connection.modifyPosition(pos.id, slMiRisque, pos.takeProfit);
                  console.log(`[MI-TP1] Mi-chemin TP1 atteint @ ${prixActuel.toFixed(2)} → SL → ${slMiRisque.toFixed(2)} (risque divisé par 2)`);
                  await positionsTrackingDb.updateAsync(
                    { positionId: pos.id },
                    { $set: { miTp1Done: true, miTp1Time: new Date(), miTp1Price: prixActuel, slMiRisque } }
                  );
                  if (typeof creerNotification === 'function') {
                    try {
                      await creerNotification(user._id, 'mi_tp_partiel',
                        `🎯 Mi-chemin TP1 atteint sur ${pos.symbol}`,
                        `Prix à mi-chemin entre entrée et TP1. SL avancé à ${slMiRisque.toFixed(2)} → risque divisé par 2. Aucun lot fermé, on garde tout pour TP1/TP2/TP3.`,
                        { miTp1: prixActuel, nouveauSL: slMiRisque });
                    } catch(e) {}
                  }
                } catch(err) { console.log('[MI-TP1] Erreur modifySL:', err.message); }
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

            // ═══ PALIER 1b : MI-CHEMIN TP2 → SL avance encore (après TP1) ═══
            // Si TP1 déjà touché et qu'on arrive à mi-chemin TP2 → SL → mi-chemin entre TP1 et TP2
            // Effet : on lock plus de profit même avant TP2
            else if (tracking.tp1Done && !tracking.tp2Done && !tracking.miTp2Done && tp2 > 0 && distribution.tp2 > 0) {
              const miTp2 = tp1 + (tp2 - tp1) * 0.5; // milieu entre TP1 et TP2
              const miTp2Atteint = isBuy ? prixActuel >= miTp2 : prixActuel <= miTp2;
              if (miTp2Atteint) {
                // SL → mi-chemin entre TP1 et entrée (lock 25% du gain TP1)
                const slMiTp2 = isBuy
                  ? entree + (tp1 - entree) * 0.25  // BUY : SL au-dessus de BE
                  : entree - (entree - tp1) * 0.25; // SELL : SL en-dessous de BE
                try {
                  await connection.modifyPosition(pos.id, slMiTp2, pos.takeProfit);
                  console.log(`[MI-TP2] Mi-chemin TP2 atteint @ ${prixActuel.toFixed(2)} → SL → ${slMiTp2.toFixed(2)} (lock 25% gain TP1)`);
                  await positionsTrackingDb.updateAsync(
                    { positionId: pos.id },
                    { $set: { miTp2Done: true, miTp2Time: new Date(), miTp2Price: prixActuel, slMiTp2 } }
                  );
                  if (typeof creerNotification === 'function') {
                    try {
                      await creerNotification(user._id, 'mi_tp_partiel',
                        `🎯 Mi-chemin TP2 atteint sur ${pos.symbol}`,
                        `Prix à mi-chemin entre TP1 et TP2. SL avancé à ${slMiTp2.toFixed(2)} → 25% du gain TP1 verrouillé.`,
                        { miTp2: prixActuel, nouveauSL: slMiTp2 });
                    } catch(e) {}
                  }
                } catch(err) { console.log('[MI-TP2] Erreur modifySL:', err.message); }
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

0. **Tendance D1 (journalière) clairement CONTRE ton signal (confidence ≥ 3/5)**
   → La tendance journalière représente le flux institutionnel de fond.
   → Trader contre elle = nager contre le courant. NE PAS TRADER.
   → Exception UNIQUE : MSS D1 récent et net qui confirme un retournement.
   → Si D1 = RANGE → pas de filtre D1, les deux sens sont possibles.

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
+ 1.5 pt: Tendance D1 alignée avec le signal (flux journalier dans ton sens)
+ 1 pt  : Tendance H1 alignée
- 2 pts : Tendance D1 CONTRE ton signal sans MSS D1 (contexte macro adverse)

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
  detecterSwings, calculerATR, calculerFibonacci, getDealingRange, detecterStructure,
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
// Note: pool MT5 retiré (jamais branché aux fonctions existantes). Sera ajouté plus tard si besoin avec tests.

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

    // ─── DEPLOY TEMPORAIRE SI NÉCESSAIRE ──────────────────────────
    // CRITIQUE : si on retourne null quand compte UNDEPLOYED, toutes les
    // protections (anti-contre-tendance, RSI extrême, etc.) sont skippées.
    // Résultat : trades contre-tendance qui passent → perte du dépôt.
    // → On deploy temporairement, on récupère les bougies, on undeploy après.
    let deployedHere = false;
    if (account.state !== 'DEPLOYED') {
      try {
        await account.deploy();
        if (typeof trackDeploy === 'function') trackDeploy(account.id, user.mt5.login);
        deployedHere = true;
        await account.waitConnected();
      } catch(deployErr) {
        console.log('[FETCH-MARKET] Deploy auto échoué pour ' + userId + ' : ' + deployErr.message);
        return null;
      }
    }

    const connection = account.getRPCConnection();
    await connection.connect();
    await connection.waitSynchronized();

    // Résolution unifiée selon serveur broker (prioritaire pour comptes STD)
    const resolved = await resolveSymbolForUser(connection, symbole || 'XAUUSD', user.mt5.server);
    if (!resolved) { console.log('[FETCH-MARKET] Symbole introuvable:', symbole); return null; }
    const symbolResolu = resolved.symbol;

    // ─── Récupération PARALLÈLE de tous les TF (1 seul deploy, 6 appels en parallèle) ─
    // D1 ajouté : filtre de tendance journalière pour bloquer les trades contre tendance
    const [candlesD1, candlesH1, candlesM30, candlesM15, candlesM5, tickInfo] = await Promise.all([
      getCandles(connection, account, symbolResolu, '1d', 30),
      getCandles(connection, account, symbolResolu, '1h', 60),
      getCandles(connection, account, symbolResolu, '30m', 60),
      getCandles(connection, account, symbolResolu, '15m', 60),
      getCandles(connection, account, symbolResolu, '5m', 60),
      connection.getSymbolPrice(symbolResolu).catch(() => null)
    ]);

    let prixActuel = null;
    if (tickInfo && tickInfo.bid) prixActuel = (tickInfo.bid + tickInfo.ask) / 2;

    const data = {
      symbolResolu,
      candlesD1,
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

    // ─── UNDEPLOY si on a deployé temporairement (économie MetaApi) ───
    // Le watchdog l'undeploy aussi en filet de sécurité, mais on le fait
    // explicitement ici pour réduire au maximum le temps deployed
    if (deployedHere) {
      // On undeploy en arrière-plan (pas await pour ne pas bloquer le retour)
      // Le wrapper TP / les autres fonctions peuvent re-deploy si besoin
      account.undeploy().then(() => {
        if (typeof trackUndeploy === 'function') trackUndeploy(account.id);
      }).catch(e => {
        console.log('[FETCH-MARKET] Undeploy auto échoué : ' + e.message);
      });
    }

    return data;
  } catch(err) {
    // En cas d'erreur, undeploy quand même si on a deployé
    if (typeof deployedHere !== 'undefined' && deployedHere) {
      try {
        const u = await db.findOneAsync({ _id: userId });
        if (u && u.mt5 && u.mt5.metaApiAccountId) {
          const a = await metaApi.metatraderAccountApi.getAccount(u.mt5.metaApiAccountId);
          if (a && a.state === 'DEPLOYED') {
            a.undeploy().then(() => { if (typeof trackUndeploy === 'function') trackUndeploy(a.id); }).catch(()=>{});
          }
        }
      } catch(e) {}
    }
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
    const candlesD1 = marketData.candlesD1 || [];
    const prixActuel = marketData.prixActuel;

    if (!candlesM15.length) return '';

    // Calcul des indicateurs (RSI Wilder + MA sur tous les TF y compris D1)
    const indic = {
      d1: {
        rsi: calculerRSI(candlesD1, 14),
        ma20: calculerMA(candlesD1, 20),
        ma50: calculerMA(candlesD1, 50),
        tendance: candlesD1.length >= 50 ? detecterTendanceRobuste(candlesD1).trend : null
      },
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

    // Ligne D1 : tendance journalière (filtre macro)
    if (indic.d1.rsi !== null || indic.d1.tendance) {
      const d1TrendLabel = indic.d1.tendance ? ` | TENDANCE J : ${indic.d1.tendance}` : '';
      txt += `D1  | RSI ${fmtRSI(indic.d1.rsi)} | MA20 ${fmtMA(indic.d1.ma20, prixActuel)} | MA50 ${fmtMA(indic.d1.ma50, prixActuel)}${d1TrendLabel}\n`;
      // Alerte explicite si tendance D1 très claire
      if (indic.d1.tendance === 'BULLISH') {
        txt += `  → 📈 TENDANCE JOURNALIÈRE BULLISH — favoriser les BUY, NE PAS VENDRE sauf MSS D1 clair\n`;
      } else if (indic.d1.tendance === 'BEARISH') {
        txt += `  → 📉 TENDANCE JOURNALIÈRE BEARISH — favoriser les SELL, NE PAS ACHETER sauf MSS D1 clair\n`;
      } else if (indic.d1.tendance === 'RANGE') {
        txt += `  → ↔️ RANGE JOURNALIER — les deux sens possibles, confluence intraday obligatoire\n`;
      }
    }

    txt += `H1  | RSI ${fmtRSI(indic.h1.rsi)} | MA20 ${fmtMA(indic.h1.ma20, prixActuel)} | MA50 ${fmtMA(indic.h1.ma50, prixActuel)}\n`;
    txt += `M15 | RSI ${fmtRSI(indic.m15.rsi)} | MA20 ${fmtMA(indic.m15.ma20, prixActuel)} | MA50 ${fmtMA(indic.m15.ma50, prixActuel)}\n`;
    txt += `M5  | RSI ${fmtRSI(indic.m5.rsi)} | MA20 ${fmtMA(indic.m5.ma20, prixActuel)} | MA50 ${fmtMA(indic.m5.ma50, prixActuel)}\n\n`;

    // Alertes synthétiques
    const alertes = [];
    const rsiExtremesSurvente = [indic.h1.rsi, indic.m15.rsi, indic.m5.rsi].filter(r => r !== null && r <= 25).length;
    const rsiExtremesSurachat = [indic.h1.rsi, indic.m15.rsi, indic.m5.rsi].filter(r => r !== null && r >= 75).length;
    if (rsiExtremesSurvente >= 2) alertes.push('⚠ RSI EN SURVENTE EXTRÊME sur plusieurs timeframes — REBOND TECHNIQUE TRÈS PROBABLE. NE PAS VENDRE sans signal de retournement clair (CHoCH M5 + bougie d\'absorption).');
    if (rsiExtremesSurachat >= 2) alertes.push('⚠ RSI EN SURACHAT EXTRÊME sur plusieurs timeframes — CORRECTION TRÈS PROBABLE. NE PAS ACHETER sans signal de retournement clair.');

    // Alerte RSI D1 extrême
    if (indic.d1.rsi !== null) {
      if (indic.d1.rsi >= 75) alertes.push(`⚠ RSI D1 ${indic.d1.rsi} — SURACHAT JOURNALIER. Éviter les BUY agressifs, correction hebdomadaire probable.`);
      else if (indic.d1.rsi <= 25) alertes.push(`⚠ RSI D1 ${indic.d1.rsi} — SURVENTE JOURNALIÈRE. Éviter les SELL agressifs, rebond hebdomadaire probable.`);
    }

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
        // FIX : aussi annulé si M6 vote contre (mouvement violent récent détecté)
        const m6ContreH1 = tH1.votes && tH1.votes.m6 && (
          (isBuy && tH1.votes.m6 === 'BEAR') || (!isBuy && tH1.votes.m6 === 'BULL')
        );
        const m6ContreM30 = tM30.votes && tM30.votes.m6 && (
          (isBuy && tM30.votes.m6 === 'BEAR') || (!isBuy && tM30.votes.m6 === 'BULL')
        );
        if ((signalContreH1 && (tH1.confidence >= 4 || m6ContreH1)) || (signalContreM30 && (tM30.confidence >= 4 || m6ContreM30))) {
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
    // Seuils calibrés pour RSI Wilder (plus stable que la version simple) :
    //   - Annulation seulement sous 25 / au-dessus de 75 (survente/surachat vrai)
    //   - Score réduit entre 25-38 / 62-75 (momentum présent)
    // NOTE : RSI 30-40 en M30 = normal sur un retracement ICT valide.
    // Un BUY dans une survente M30 peut être exactement le bon timing (discount).
    // On ne bloque que les extrêmes réels, pas les retracements normaux.
    try {
      const candlesM30 = marketData.candlesM30 || [];
      if (candlesM30.length >= 15) {
        const rsiM30 = calculerRSI(candlesM30, 14);
        if (rsiM30 !== null) {
          if (isBuy && rsiM30 < 25) {
            tradeAnnule = true;
            alertes.push(`🚫 RSI M30 ${rsiM30.toFixed(1)} < 25 → survente extrême M30, momentum baissier très fort, BUY annulé`);
          } else if (!isBuy && rsiM30 > 75) {
            tradeAnnule = true;
            alertes.push(`🚫 RSI M30 ${rsiM30.toFixed(1)} > 75 → surachat extrême M30, momentum haussier très fort, SELL annulé`);
          } else if (isBuy && rsiM30 < 38) {
            scoreReduit = true;
            alertes.push(`RSI M30 ${rsiM30.toFixed(1)} < 38 → momentum baissier modéré M30, score réduit`);
          } else if (!isBuy && rsiM30 > 62) {
            scoreReduit = true;
            alertes.push(`RSI M30 ${rsiM30.toFixed(1)} > 62 → momentum haussier modéré M30, score réduit`);
          }
        }
      }
    } catch(err) {
      console.log('[PROTECTION-RSI-M30] Erreur:', err.message);
    }

    // ─── PROTECTION 7 : COHÉRENCE PREMIUM/DISCOUNT vs SENS ─────────
    // BUY en PREMIUM = achat au sommet du range → piège classique ICT.
    // Exception : MSS_BULLISH ou BOS_BULLISH récent (cassure de structure
    // confirmée qui justifie un entry en premium avec continuation).
    if (parsed.premiumDiscount && parsed.structureEvent !== undefined) {
      const pd = String(parsed.premiumDiscount).toUpperCase();
      const ev = String(parsed.structureEvent || 'NONE').toUpperCase();
      const structureHaussiere = ev === 'MSS_BULLISH' || ev === 'BOS_BULLISH';
      const structurebaissiere = ev === 'MSS_BEARISH' || ev === 'BOS_BEARISH';
      if (isBuy && pd === 'PREMIUM' && !structureHaussiere) {
        tradeAnnule = true;
        alertes.push(`🚫 BUY en zone PREMIUM sans MSS/BOS bullish → achat au sommet du range, violation ICT, annulé`);
      } else if (!isBuy && pd === 'DISCOUNT' && !structurebaissiere) {
        tradeAnnule = true;
        alertes.push(`🚫 SELL en zone DISCOUNT sans MSS/BOS bearish → vente en bas du range, violation ICT, annulé`);
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
    // Bloque uniquement les créneaux avec forte probabilité de news réelle.
    // CPI/FOMC/BCE ne sortent pas chaque semaine → on utilise des heuristiques
    // ciblées pour éviter de bloquer 3 mercredis/mois pour rien.
    //
    // Règles retenues :
    //   NFP   : 1er vendredi du mois 14h30 UTC (certain)
    //   CPI   : 2e ou 3e mercredi du mois 14h30 UTC (≈ 90% du temps)
    //   FOMC  : mercredi semaines paires (8×/an → ~4 mercredis pairs/mois sur 2)
    //   BCE   : jeudi 13h45 UTC, 1 jeudi sur 6 environ (8×/an)
    //   → On bloque uniquement sur les semaines statistiquement probables.
    try {
      const now = new Date();
      const dayUTC = now.getUTCDay();
      const dateUTC = now.getUTCDate();
      const hourUTC = now.getUTCHours();
      const minUTC = now.getUTCMinutes();
      const totalMinUTC = hourUTC * 60 + minUTC;
      const WINDOW = 30;
      const dansLaFenetre = (cibleH, cibleM) => {
        const cibleTotal = cibleH * 60 + cibleM;
        return Math.abs(totalMinUTC - cibleTotal) <= WINDOW;
      };

      const newsAlerte = [];

      // NFP : 1er vendredi du mois (certain) — dateUTC <= 7
      if (dayUTC === 5 && dateUTC <= 7 && dansLaFenetre(14, 30)) {
        newsAlerte.push('NFP (1er vendredi du mois)');
      }

      // CPI US : 2e ou 3e mercredi du mois à 14h30 UTC
      // dateUTC 8-21 = 2e ou 3e semaine → couvre ~90% des publications CPI
      if (dayUTC === 3 && dateUTC >= 8 && dateUTC <= 21 && dansLaFenetre(14, 30)) {
        newsAlerte.push('CPI US probable (2e/3e mercredi du mois)');
      }

      // FOMC : ~8 fois/an, toujours un mercredi à 20h UTC
      // Heuristique : semaines 2 et 4 du mois (dateUTC 8-15 ou 22-28)
      if (dayUTC === 3 && (
        (dateUTC >= 8 && dateUTC <= 15) || (dateUTC >= 22 && dateUTC <= 28)
      ) && dansLaFenetre(20, 0)) {
        newsAlerte.push('FOMC probable (mercredi sem. 2 ou 4)');
      }

      // BCE : ~8 fois/an jeudi 13h45 UTC
      // Heuristique : 1er et 3e jeudi du mois (dateUTC <= 7 ou 15-21)
      if (dayUTC === 4 && (dateUTC <= 7 || (dateUTC >= 15 && dateUTC <= 21))
          && (dansLaFenetre(13, 45) || dansLaFenetre(14, 30))) {
        newsAlerte.push('BCE probable (1er/3e jeudi du mois)');
      }

      if (newsAlerte.length > 0) {
        tradeAnnule = true;
        alertes.push(`🚫 FENÊTRE NEWS ROUGE : ${newsAlerte.join(', ')} — trading suspendu ±30 min (volatilité non analysable)`);
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

    // ─── PROTECTION 10 : FILTRE TENDANCE DAILY D1 ─────────────────────
    // Dernier rempart : la tendance journalière est le contexte macro qui
    // prime sur tout signal intraday. Si D1 est BEARISH avec confidence >= 3
    // et qu'on veut BUY, c'est presque toujours un piège (trade contre la
    // "big picture" institutionnelle). Annulation sauf :
    //   - MSS D1 récent aligné avec le signal (vrai retournement journalier)
    //   - Confidence D1 faible (< 3 sur 5) → seulement score réduit
    //   - Range D1 → pas de filtre (les deux sens possibles)
    //
    // COHÉRENCE AVEC LA PROTECTION 5 : Protection 5 filtre H1+M30,
    // Protection 10 filtre D1. Pas de doublon — niveaux différents.
    // Le filtre D1 est plus doux : annule seulement si confidence forte (≥3).
    try {
      const candlesD1 = marketData.candlesD1 || [];
      if (candlesD1.length >= 50) {
        const tD1 = detecterTendanceRobuste(candlesD1);
        console.log(`[TENDANCE-D1] D1=${tD1.trend} (${tD1.confidence}/5)`);

        // Stocker pour traçabilité
        parsed.tendanceServerD1 = tD1.trend;
        parsed.tendanceConfidenceD1 = tD1.confidence;

        const signalContreD1 = (isBuy && tD1.trend === 'BEARISH') || (!isBuy && tD1.trend === 'BULLISH');

        if (signalContreD1 && tD1.trend !== 'RANGE') {
          // Vérifier si MSS D1 récent override (retournement journalier confirmé)
          const structD1 = detecterStructure(candlesD1, 3);
          const mssD1Aligne = structD1.event && (
            (isBuy && structD1.event.type === 'MSS_BULLISH') ||
            (!isBuy && structD1.event.type === 'MSS_BEARISH')
          );

          if (mssD1Aligne) {
            scoreReduit = true;
            alertes.push(`⚠️ Tendance D1 contre ${parsed.decision} (${tD1.trend} ${tD1.confidence}/5) MAIS MSS_${isBuy ? 'BULLISH' : 'BEARISH'} D1 détecté → retournement possible, score réduit`);
          } else if (tD1.confidence >= 4) {
            // 4/5 ou 5/5 = annulation (équilibré pour WR 60%)
            tradeAnnule = true;
            alertes.push(`🚫 CONTRE-TENDANCE D1 FORTE : D1=${tD1.trend} (${tD1.confidence}/5) vs ${parsed.decision} — annulé`);
          } else if (tD1.confidence === 3) {
            scoreReduit = true;
            alertes.push(`⚠️ Tendance D1 ${tD1.trend} (3/5) contre ${parsed.decision} — score réduit`);
          }
          // confidence <= 2 → silencieux (D1 trop incertain)
        }
      } else {
        console.log('[PROTECTION-D1] Pas assez de bougies D1 (' + candlesD1.length + '/50)');
      }
    } catch(errD1) {
      console.log('[PROTECTION-D1] Erreur:', errD1.message);
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

    // Résolution unifiée selon serveur
    const resolved = await resolveSymbolForUser(connection, symbole, user.mt5.server);
    const prix = resolved ? resolved.mid : null;

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
  // OPTI : utiliser le cache marketData au lieu de redéployer le compte MetaApi
  const marketData = await fetchAllMarketData(userId, symbole);
  const prixActuel = marketData?.prixActuel;
  if (!prixActuel) {
    console.log('[REAJUST] Prix actuel indisponible (cache), on garde l\'entrée IA');
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

    // ─── ANALYSE ICT COMPLÈTE (DOL, P/D, MSS, kill zone, ATR, FIBO) ─
    const analyseICT = await ict.analyseComplete(candlesM15, candlesH1, candlesM5);

    // Cache global : utilisé par /analyze pour récupérer Fibo + détecter conflits
    if (!global._ictCache) global._ictCache = {};
    // Stocker aussi le RSI M15 réel pour les hard-blocks post-IA
    const _rsiM15PourCache = calculerRSI(candlesM15, 14);
    const _rsiH1PourCache  = calculerRSI(candlesH1 || [], 14);
    global._ictCache[userId] = { analyse: analyseICT, time: Date.now(), rsiM15: _rsiM15PourCache, rsiH1: _rsiH1PourCache };

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
    const userOwner = await db.findOneAsync({ _id: analyse.userId });
    if (!hasPremiumAccess(userOwner)) return;
  } catch(e) { return; }

  try {
    // FILTRE QUALITE : exiger profit >= 1R pour considérer comme setup gagnant
    // Sinon les trades à +0.5R polluent la base d'apprentissage
    const slDist = analyse.slPips || 0;
    const profit = analyse.tradeProfit;
    if (analyse.entree && analyse.sl) {
      const eN = parseFloat(analyse.entree);
      const sN = parseFloat(analyse.sl);
      const lots = parseFloat(analyse.lots) || 0.10;
      const dist = Math.abs(eN - sN);
      let mult = 1;
      const inst = (analyse.instrument || 'XAUUSD').toUpperCase();
      if (inst.includes('XAU')) mult = 100;
      else if (inst.includes('JPY')) mult = 1000;
      else if (inst.match(/EUR|GBP|AUD|NZD|CHF|CAD/)) mult = 100000;
      const risqueDol = dist * lots * mult;
      const ratioR = risqueDol > 0 ? profit / risqueDol : 0;
      if (ratioR < 1.0) {
        console.log('[SETUP-GAGNANT] Skip — ' + profit.toFixed(2) + '\$ < 1R (' + risqueDol.toFixed(2) + '\$)');
        return;
      }
    }
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
      accountId: analyse.accountId || null,
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

async function getBlocSetupsGagnants(userId, instrument, accountId) {
  // FIX multi-comptes : filtre par accountId si fourni
  const setupQuery = { userId, instrument: instrument || 'XAUUSD' };
  if (accountId) setupQuery.accountId = accountId;
  try {
    const setups = await setupsGagnantsDb.findAsync(setupQuery);
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

async function getLeconsPourPrompt(userId, accountId) {
  // FIX multi-comptes : si accountId fourni, on filtre les leçons pour ce compte
  // Sinon on charge tout (rétrocompat)
  const baseQuery = { userId };
  if (accountId) baseQuery.accountId = accountId;
  try {
    const lecons = await leconsDb.findAsync(baseQuery);
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
  try {
    const user = await db.findOneAsync({ _id: userId });
    if (!user) return null;

    // GATING : post-mortem auto uniquement Pro/Elite
    if (!hasPremiumAccess(user)) return null;

    // FIX BUG : la leçon doit être générée MÊME sans MT5 connecté ou deployed
    // On utilise les données déjà présentes dans l'analyse (pas besoin de re-fetch bougies)
    const symbole = (analyse.instrument || 'XAUUSD').toUpperCase();
    const tempsCloture = new Date(analyse.tradeClotureTemps || analyse.createdAt);

    // Tentative de récupération bougies UNIQUEMENT si MT5 connecté ET deployed (optionnel)
    let candles = [];
    let obs = [], fvgs = [];
    if (metaApi && user.mt5 && user.mt5.metaApiAccountId) {
      try {
        const account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
        if (account.state === 'DEPLOYED') {
          const connection = account.getRPCConnection();
          await connection.connect();
          await connection.waitSynchronized();
          const debut = new Date(tempsCloture.getTime() - 30 * 5 * 60 * 1000);
          const resolvedPM = await resolveSymbolForUser(connection, symbole, user.mt5.server);
          if (resolvedPM) {
            try { candles = await connection.getHistoricalCandles(resolvedPM.symbol, '5m', debut, 30) || []; } catch(e) {}
          }
        }
      } catch(e) { /* on continue sans les bougies */ }
    }

    // Détecter OB/FVG SI on a les bougies, sinon on s'en passe
    if (candles.length > 0) {
      try { obs = detecterOrderBlocks(candles); } catch(e) {}
      try { fvgs = detecterFairValueGaps(candles); } catch(e) {}
    }

    // Construction du résumé textuel pour l'IA
    // Si bougies dispo, on les inclut. Sinon on se base juste sur l'analyse.
    const dernieresBougies = candles.length > 0 ? candles.slice(-10).map(c => ({
      time: new Date(c.time).toISOString(),
      o: c.open.toFixed(2),
      h: c.high.toFixed(2),
      l: c.low.toFixed(2),
      c: c.close.toFixed(2)
    })) : [];
    const bougiesDispoText = candles.length > 0 ? `\nDERNIÈRES BOUGIES M5 AVANT SL :\n${JSON.stringify(dernieresBougies, null, 2)}\n` : '\n(Bougies non disponibles — analyse rétrospective basée sur les paramètres du trade)\n';

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

DONNÉES OBJECTIVES DU MARCHÉ :
${bougiesDispoText}
- OB bullish détectés : ${obs.bullish ? obs.bullish.length : 0} (zones: ${obs.bullish ? obs.bullish.map(o => o.zone.low.toFixed(2) + '-' + o.zone.high.toFixed(2)).join(', ') || 'aucun' : 'N/A'})
- OB bearish détectés : ${obs.bearish ? obs.bearish.length : 0} (zones: ${obs.bearish ? obs.bearish.map(o => o.zone.low.toFixed(2) + '-' + o.zone.high.toFixed(2)).join(', ') || 'aucun' : 'N/A'})
- FVG bullish : ${fvgs.bullish ? fvgs.bullish.length : 0}, FVG bearish : ${fvgs.bearish ? fvgs.bearish.length : 0}

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
      accountId: analyse.accountId || null,
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
// ═══════════════════════════════════════════════════════════════════
// 🧠 PATTERN D'ERREURS PERSONNALISÉ (Pro/Elite uniquement)
// ═══════════════════════════════════════════════════════════════════
// Analyse les 30 derniers trades clos d'un user pour identifier ses
// patterns d'erreur récurrents. Injecté dans le prompt pour que l'IA
// évite de reproduire les mêmes setups foireux.
//
// Filtres anti-bruit :
//   - Min 5 trades clos pour activer
//   - Min 3 occurrences par pattern
//   - Cache 30 min pour éviter recalculs
//
// Identifie : sessions perdantes, déséquilibre BUY/SELL, zones perdantes

const _patternErreursCache = new Map();
const PATTERN_CACHE_TTL_MS = 30 * 60 * 1000;

async function getPatternErreursPersonnalise(userId, user) {
  if (!hasPremiumAccess(user)) return null;

  const cached = _patternErreursCache.get(userId);
  if (cached && (Date.now() - cached.time) < PATTERN_CACHE_TTL_MS) {
    return cached.patterns;
  }

  try {
    const tradesClots = await analysesDb.findAsync({
      userId,
      $or: [
        { feedbackResult: { $in: ['tp', 'sl'] } },
        { tradeProfit: { $exists: true } }
      ]
    });

    if (!tradesClots || tradesClots.length < 5) return null;

    const tradesRecents = tradesClots
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 30);

    let totalGagnes = 0, totalPerdus = 0;
    const parSession = {
      ASIAN: { tp:0, sl:0 }, LONDON: { tp:0, sl:0 },
      NY: { tp:0, sl:0 }, AUTRE: { tp:0, sl:0 }
    };
    const parDecision = { BUY: { tp:0, sl:0 }, SELL: { tp:0, sl:0 } };
    const parZone = {
      DISCOUNT: { tp:0, sl:0 },
      PREMIUM: { tp:0, sl:0 },
      EQUILIBRIUM: { tp:0, sl:0 }
    };

    for (const t of tradesRecents) {
      const isWin = (t.feedbackResult === 'tp') || (typeof t.tradeProfit === 'number' && t.tradeProfit > 0);
      const isLoss = (t.feedbackResult === 'sl') || (typeof t.tradeProfit === 'number' && t.tradeProfit < 0);
      if (!isWin && !isLoss) continue;
      if (isWin) totalGagnes++; else totalPerdus++;

      const heure = new Date(t.createdAt).getUTCHours();
      let session = 'AUTRE';
      if (heure >= 0 && heure < 7) session = 'ASIAN';
      else if (heure >= 7 && heure < 13) session = 'LONDON';
      else if (heure >= 13 && heure < 21) session = 'NY';
      parSession[session][isWin ? 'tp' : 'sl']++;

      const dec = (t.decision || '').toUpperCase();
      if (parDecision[dec]) parDecision[dec][isWin ? 'tp' : 'sl']++;

      const zone = (t.premiumDiscount || '').toUpperCase();
      if (parZone[zone]) parZone[zone][isWin ? 'tp' : 'sl']++;
    }

    const totalAnalyses = totalGagnes + totalPerdus;
    if (totalAnalyses < 5) return null;
    const winRateGlobal = Math.round(totalGagnes / totalAnalyses * 100);

    const erreurs = [];
    const succes = [];

    for (const [sess, data] of Object.entries(parSession)) {
      const total = data.tp + data.sl;
      if (total < 3) continue;
      const wr = Math.round(data.tp / total * 100);
      if (wr < 30 && data.sl >= 2) erreurs.push(`Session ${sess} : ${data.sl} pertes / ${total} (${wr}% WR) — éviter`);
      else if (wr >= 65 && data.tp >= 2) succes.push(`Session ${sess} : ${wr}% WR (${data.tp}/${total}) — privilégier`);
    }

    for (const dec of ['BUY', 'SELL']) {
      const d = parDecision[dec];
      const total = d.tp + d.sl;
      if (total < 4) continue;
      const wr = Math.round(d.tp / total * 100);
      if (wr < 30) erreurs.push(`${dec} : ${wr}% WR sur ${total} trades — déséquilibre`);
      else if (wr >= 65) succes.push(`${dec} : ${wr}% WR sur ${total} trades — fort`);
    }

    for (const [zone, data] of Object.entries(parZone)) {
      const total = data.tp + data.sl;
      if (total < 3) continue;
      const wr = Math.round(data.tp / total * 100);
      if (wr < 30 && data.sl >= 2) erreurs.push(`Zone ${zone} : ${data.sl} pertes / ${total} (${wr}% WR)`);
    }

    if (erreurs.length === 0 && succes.length === 0) {
      const patterns = `📊 HISTORIQUE TRADER : ${totalAnalyses} trades clos, ${winRateGlobal}% win rate. Pas de pattern marquant.`;
      _patternErreursCache.set(userId, { patterns, time: Date.now() });
      return patterns;
    }

    let txt = `📊 HISTORIQUE TRADER (${totalAnalyses} trades, ${winRateGlobal}% WR) :\n`;
    if (erreurs.length > 0) {
      txt += `⚠️ PATTERNS À ÉVITER :\n`;
      erreurs.slice(0, 4).forEach(e => txt += `  • ${e}\n`);
    }
    if (succes.length > 0) {
      txt += `✅ PATTERNS GAGNANTS :\n`;
      succes.slice(0, 3).forEach(s => txt += `  • ${s}\n`);
    }
    txt += `→ Tiens compte de ces patterns. Si tu proposes un trade qui correspond à un pattern d'erreur, justifie ou annule.`;

    if (txt.length > 800) txt = txt.substring(0, 797) + '...';
    _patternErreursCache.set(userId, { patterns: txt, time: Date.now() });
    return txt;
  } catch(e) {
    console.log('[PATTERN-ERREURS]', e.message);
    return null;
  }
}

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


// ═══════════════════════════════════════════════════════════════════
// 📧 ALERTE EMAIL SETUP A+ (score >= 8) — broadcast à tous les clients
// ═══════════════════════════════════════════════════════════════════
// Déclenché automatiquement après chaque analyse dont le score >= 8
// Envoie un email à tous les clients abonnés (subscribed=true + non bannis)
// avec le setup complet : direction, instrument, entrée, SL, TP1/2/3, score.
// Envoi en parallèle via Promise.allSettled (1 échec ne bloque pas les autres).

async function envoyerAlerteSetupAPlus(parsed, analyseId) {
  const score = parseFloat(parsed.score) || 0;
  if (score < 8) return;
  if (parsed.decision !== 'BUY' && parsed.decision !== 'SELL') return;

  try {
    // GATING : seulement les Pro/Elite reçoivent les alertes A+
    // Les free/starter ne reçoivent pas (incentive à upgrade)
    const clients = await db.findAsync({
      role: { $ne: 'admin' },
      subscribed: true,
      isVerified: true,
      banned: { $ne: true },
      plan: { $in: ['premium', 'elite', 'pro'] }
    });

    if (!clients || clients.length === 0) {
      console.log('[ALERTE-EMAIL] Aucun client abonné à notifier');
      return;
    }

    const isBuy   = parsed.decision === 'BUY';
    const couleur  = isBuy ? '#00ff88' : '#ff3060';
    const emoji    = isBuy ? '🟢' : '🔴';
    const scoreEmoji = score >= 9 ? '🏆' : '⭐';
    const urgence  = score >= 9.5 ? '🔴 ULTRA URGENT' : score >= 9 ? '🟠 URGENT' : '🟡 SETUP A+';

    const instrument = parsed.instrument || 'XAUUSD';
    const entree     = parsed.entree || parsed.entry || '—';
    const sl         = parsed.sl     || '—';
    const tp1        = parsed.tp1    || '—';
    const tp2        = parsed.tp2    || '—';
    const tp3        = parsed.tp3    || '—';
    const lots       = parsed.lots   || '—';
    const raison     = parsed.raisonCourte || parsed.raison || parsed.analyse || "Setup validé par l\'IA";
    // Lien profond vers le site avec ouverture auto du modal du setup
    // Le frontend détecte ?aplus=ID dans l'URL et ouvre le modal correspondant
    const lienApp    = BASE_URL + '/?aplus=' + (analyseId || '');
    const idCourt    = analyseId ? String(analyseId).substring(0, 8) : '—';

    const htmlEmail = `<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#020510;font-family:Arial,sans-serif;">
  <div style="max-width:560px;margin:0 auto;padding:30px 16px;">
    <div style="text-align:center;margin-bottom:24px;">
      <div style="font-size:11px;letter-spacing:4px;color:#00f5ff;text-transform:uppercase;margin-bottom:6px;">AI-MAZZA</div>
      <div style="height:1px;background:linear-gradient(90deg,transparent,#00f5ff,transparent);margin-bottom:18px;opacity:0.4;"></div>
      <div style="font-size:13px;letter-spacing:3px;color:rgba(255,255,255,0.5);text-transform:uppercase;">${urgence}</div>
    </div>
    <div style="background:rgba(0,20,50,0.9);border:2px solid ${couleur};border-radius:6px;padding:20px;text-align:center;margin-bottom:16px;">
      <div style="font-size:36px;font-weight:900;letter-spacing:6px;color:${couleur};margin-bottom:6px;">${emoji} ${parsed.decision} ${instrument}</div>
      <div style="font-size:13px;color:rgba(255,255,255,0.5);letter-spacing:2px;">SETUP DÉTECTÉ PAR L'IA</div>
    </div>
    <div style="background:rgba(0,10,30,0.9);border:1px solid rgba(0,245,255,0.15);border-radius:6px;padding:16px;margin-bottom:16px;text-align:right;">
      <span style="color:rgba(255,255,255,0.4);font-size:11px;letter-spacing:2px;text-transform:uppercase;float:left;padding-top:6px;">Score IA</span>
      <span style="font-size:28px;font-weight:900;color:${score >= 9 ? '#ffd700' : '#00ff88'};">${scoreEmoji} ${score}/10</span>
    </div>
    <div style="background:rgba(0,20,50,0.9);border:1px solid rgba(0,245,255,0.15);border-radius:6px;padding:16px;margin-bottom:16px;">
      <div style="font-size:10px;letter-spacing:3px;color:rgba(0,245,255,0.6);text-transform:uppercase;margin-bottom:14px;">📊 Niveaux du trade</div>
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="padding:8px 0;color:rgba(255,255,255,0.4);font-size:12px;text-transform:uppercase;">Entrée</td><td style="padding:8px 0;color:#fff;font-size:16px;font-weight:bold;text-align:right;">${entree}</td></tr>
        <tr style="border-top:1px solid rgba(255,255,255,0.05);"><td style="padding:8px 0;color:rgba(255,48,96,0.8);font-size:12px;text-transform:uppercase;">Stop Loss</td><td style="padding:8px 0;color:#ff3060;font-size:16px;font-weight:bold;text-align:right;">${sl}</td></tr>
        <tr style="border-top:1px solid rgba(255,255,255,0.05);"><td style="padding:8px 0;color:rgba(0,255,136,0.8);font-size:12px;text-transform:uppercase;">TP1</td><td style="padding:8px 0;color:#00ff88;font-size:16px;font-weight:bold;text-align:right;">${tp1}</td></tr>
        <tr style="border-top:1px solid rgba(255,255,255,0.05);"><td style="padding:8px 0;color:rgba(0,255,136,0.6);font-size:12px;text-transform:uppercase;">TP2</td><td style="padding:8px 0;color:rgba(0,255,136,0.7);font-size:14px;font-weight:bold;text-align:right;">${tp2}</td></tr>
        <tr style="border-top:1px solid rgba(255,255,255,0.05);"><td style="padding:8px 0;color:rgba(0,255,136,0.5);font-size:12px;text-transform:uppercase;">TP3</td><td style="padding:8px 0;color:rgba(0,255,136,0.5);font-size:14px;font-weight:bold;text-align:right;">${tp3}</td></tr>
        ${lots !== '—' ? '<tr style="border-top:1px solid rgba(255,255,255,0.05);"><td style="padding:8px 0;color:rgba(255,215,0,0.7);font-size:12px;text-transform:uppercase;">Lots</td><td style="padding:8px 0;color:#ffd700;font-size:14px;font-weight:bold;text-align:right;">' + lots + '</td></tr>' : ''}
      </table>
    </div>
    <div style="background:rgba(128,0,255,0.06);border:1px solid rgba(128,0,255,0.2);border-radius:6px;padding:16px;margin-bottom:20px;">
      <div style="font-size:10px;letter-spacing:3px;color:rgba(128,0,255,0.7);text-transform:uppercase;margin-bottom:10px;">🤖 Analyse IA</div>
      <div style="font-size:13px;color:rgba(255,255,255,0.7);line-height:1.6;">${raison}</div>
    </div>
    <div style="text-align:center;margin-bottom:24px;">
      <a href="${lienApp}" style="display:inline-block;background:${couleur};color:#020510;padding:16px 40px;text-decoration:none;font-weight:bold;font-size:13px;letter-spacing:3px;text-transform:uppercase;border-radius:3px;">${isBuy ? '🟢' : '🔴'} VOIR LE SETUP COMPLET</a>
    </div>
    <div style="text-align:center;padding:16px;border-top:1px solid rgba(255,255,255,0.06);">
      <p style="font-size:11px;color:rgba(255,255,255,0.25);line-height:1.5;margin:0;">⚠️ Ce signal est fourni à titre informatif. Le trading comporte des risques.<br><span style="color:rgba(255,255,255,0.15);">AI-Mazza — Setup #${idCourt}</span></p>
    </div>
  </div>
</body>
</html>`;

    console.log('[ALERTE-EMAIL] Envoi setup A+ (score ' + score + ') à ' + clients.length + ' client(s)...');
    const envois = clients.map(client =>
      transporter.sendMail({
        from: '"AI-Mazza 🔥" <' + process.env.BREVO_SENDER + '>',
        to: client.email,
        subject: emoji + ' SETUP A+ — ' + parsed.decision + ' ' + instrument + ' | Score ' + score + '/10',
        html: htmlEmail
      }).then(() => console.log('[ALERTE-EMAIL] ✅ ' + client.email))
        .catch(err => console.log('[ALERTE-EMAIL] ❌ ' + client.email + ' : ' + err.message))
    );
    await Promise.allSettled(envois);
    console.log('[ALERTE-EMAIL] Broadcast terminé (' + clients.length + ' client(s))');

  } catch(err) {
    console.log('[ALERTE-EMAIL] Erreur générale:', err.message);
  }
}

async function getFacteurRisque(userId, capital) {
  if (!capital || capital <= 0) return { facteur: 1, alerte: null, mode: 'NORMAL' };
  try {
    const debutJour = new Date();
    debutJour.setHours(0, 0, 0, 0);
    const il_y_a_24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const il_y_a_7j = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const analysesJour = await analysesDb.findAsync({ userId, createdAt: { $gte: debutJour } });
    const analyses24h = await analysesDb.findAsync({ userId, createdAt: { $gte: il_y_a_24h } });
    const analyses7j = await analysesDb.findAsync({ userId, createdAt: { $gte: il_y_a_7j } });

    let perteJour = 0, nbSL = 0;
    for (const a of analysesJour) {
      if (typeof a.tradeProfit === 'number' && a.tradeProfit < 0) {
        perteJour += Math.abs(a.tradeProfit);
        nbSL++;
      } else if (a.feedbackResult === 'sl' && a.lots && a.slPips) {
        const slDollars = a.slPips < 30 ? a.slPips : a.slPips / 10;
        perteJour += slDollars * 100 * a.lots;
        nbSL++;
      }
    }
    const pertePct = (perteJour / capital) * 100;

    // PROTECTIONS (priorité absolue, override tout)
    if (pertePct >= 10) return { facteur: 0.25, mode: 'PRESERVATION', alerte: `⚠️ Drawdown jour ${pertePct.toFixed(1)}% — lot réduit de 75% (protection capital)` };
    if (pertePct >= 5)  return { facteur: 0.5,  mode: 'VIGILANCE',   alerte: `⚠️ Drawdown jour ${pertePct.toFixed(1)}% — lot réduit de 50% (protection capital)` };
    if (nbSL >= 2)      return { facteur: 0.5,  mode: 'VIGILANCE',   alerte: `⚠️ Déjà 2 SL aujourd'hui — lot réduit de 50% (anti-tilt)` };

    // Mode profit : calcul du gain total réalisé (vs capital initial qu'on suppose = capital - gains)
    let gainCumule = 0;
    let nbTP = 0;
    for (const a of analyses7j) {
      if (typeof a.tradeProfit === 'number' && a.tradeProfit > 0) {
        gainCumule += a.tradeProfit;
        nbTP++;
      }
    }
    const nbTradesAvecResult = analyses7j.filter(a => typeof a.tradeProfit === 'number').length;
    const winRate7j = nbTradesAvecResult > 0 ? (nbTP / nbTradesAvecResult) : 0;

    // SL dans les 24h ? → pas de mode profit (sécurité)
    const slDernieres24h = analyses24h.some(a =>
      (typeof a.tradeProfit === 'number' && a.tradeProfit < 0) || a.feedbackResult === 'sl'
    );

    // 🔥 MODE SURF (très bon état)
    // Conditions : pas de SL 24h + gain >= 15% + WR >= 60%
    if (!slDernieres24h && gainCumule / capital >= 0.15 && winRate7j >= 0.6 && nbTradesAvecResult >= 3) {
      return {
        facteur: 1,
        mode: 'SURF',
        gainCumule: +gainCumule.toFixed(2),
        gainPct: +((gainCumule / capital) * 100).toFixed(1),
        winRate7j: +(winRate7j * 100).toFixed(0),
        bonusPctScore9: 5,  // 5% sur les gains pour score 9
        bonusPctScore10: 7, // 7% sur les gains pour score 10
        alerte: `🔥 MODE SURF activé — gain +${((gainCumule / capital) * 100).toFixed(1)}% sur 7j, WR ${(winRate7j * 100).toFixed(0)}%. Setups 9-10 peuvent pousser jusqu'à 7% des gains.`
      };
    }

    // 🟢 MODE VAGUE VERTE
    // Conditions : pas de SL 24h + gain >= 5%
    if (!slDernieres24h && gainCumule / capital >= 0.05 && nbTradesAvecResult >= 2) {
      return {
        facteur: 1,
        mode: 'VAGUE_VERTE',
        gainCumule: +gainCumule.toFixed(2),
        gainPct: +((gainCumule / capital) * 100).toFixed(1),
        winRate7j: +(winRate7j * 100).toFixed(0),
        bonusPctScore9: 4,  // 4% sur les gains pour score 9
        bonusPctScore10: 5, // 5% sur les gains pour score 10
        alerte: `🟢 MODE VAGUE VERTE — gain +${((gainCumule / capital) * 100).toFixed(1)}% sur 7j. Setups 9-10 utilisent un bonus sur les gains.`
      };
    }

    return { facteur: 1, mode: 'NORMAL', alerte: null };
  } catch(err) {
    return { facteur: 1, mode: 'NORMAL', alerte: null };
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
// Cache : userId → dernier check timestamp (évite double-check si plusieurs triggers proches)
const _wrapperCheckCache = new Map();
const WRAPPER_MIN_INTERVAL_MS = 2 * 60 * 1000; // 2 min minimum entre 2 checks du même user
// FIX ÉCO : cache erreurs récentes pour éviter de re-tenter sans cesse les comptes qui échouent
const _wrapperErrorCache = new Map(); // userId → timestamp dernière erreur
const ERROR_COOLDOWN_MS = 15 * 60 * 1000; // FIX : 15 min de cooldown (au lieu de 5) pour réduire les Failed to subscribe

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

// FIX COÛT : Wrapper TP à 10 min (au lieu de 5)
// Les déclenchements immédiats à 10s/30s/60s/120s après placement couvrent les exécutions rapides
// → cycle de 10 min suffisant pour le reste (BE qui doit bouger, trailing, etc.)
setInterval(gererTpPartielsWrapper, 10 * 60 * 1000);
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
      let apprentissageDeployedHere = false;
      let apprentissageAccount = null;
      try {
        const user = await db.findOneAsync({ _id: userId });
        if (!user || !user.mt5 || !user.mt5.metaApiAccountId) continue;

        // GATING : apprentissage IA uniquement Pro/Elite (free/starter exclu)
        if (!hasPremiumAccess(user)) continue;

        apprentissageAccount = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);

        // ─── FIX COÛT METAAPI : ne deploy QUE si nécessaire ─────────────
        // Si déjà deployed (ex: client connecté), on profite de la connexion existante.
        // Si undeployed, on deploy temporairement et on referme après → économie maximale.
        const account = apprentissageAccount;
        if (account.state !== 'DEPLOYED') {
          try {
            await account.deploy();
            if (typeof trackDeploy === 'function') trackDeploy(account.id, user.mt5.login);
            apprentissageDeployedHere = true;
            await account.waitConnected();
          } catch(deployErr) {
            console.log('[APPRENTISSAGE] Deploy impossible pour ' + userId + ':', deployErr.message);
            continue;
          }
        }

        const connection = account.getRPCConnection();
        await connection.connect();
        await connection.waitSynchronized();

        // FIX BUG : selon SDK MetaApi, getDealsByTimeRange retourne soit un array,
        // soit un objet { deals: [...] }. On normalise pour éviter "deals.filter is not a function"
        let dealsRaw = await connection.getDealsByTimeRange(dateLimit, new Date());
        const deals = Array.isArray(dealsRaw) ? dealsRaw : (dealsRaw && Array.isArray(dealsRaw.deals) ? dealsRaw.deals : []);

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
        // ─── FIX COÛT : undeploy si on a deployé temporairement ───
        if (apprentissageDeployedHere && apprentissageAccount) {
          try {
            await apprentissageAccount.undeploy();
            if (typeof trackUndeploy === 'function') trackUndeploy(apprentissageAccount.id);
            apprentissageDeployedHere = false;
          } catch(e) {}
        }
      } catch(err) {
        // Undeploy même en cas d'erreur
        if (apprentissageDeployedHere && apprentissageAccount) {
          try { await apprentissageAccount.undeploy(); if (typeof trackUndeploy === 'function') trackUndeploy(apprentissageAccount.id); } catch(e) {}
        }
        if (!err.message.includes('not found')) console.log('[APPRENTISSAGE] Erreur user:', err.message);
      }
    }
  } catch(err) { console.log('[APPRENTISSAGE] Erreur globale:', err.message); }
}
// FIX COÛT : apprentissage à 2h (au lieu de 30 min) = -75% de deploys
// L'apprentissage n'est PAS urgent, attendre 2h ne change rien
setInterval(surveillerTradesEtApprendre, 2 * 60 * 60 * 1000);

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

// FIX : si visiteur PAS connecté → landing commerciale, sinon → app principale
app.get('/', (req, res) => {
  // OPTION B : TOUT LE MONDE voit la landing en premier (même connectés)
  // L'app est accessible via /app pour les connectés
  console.log('[ROUTE-/] Serving landing à tous (option B)');
  const landingPath = path.join(__dirname, 'public/landing.html');
  console.log('[ROUTE-/] Visiteur non connecté → essai landing à ' + landingPath);
  console.log('[ROUTE-/] Fichier landing existe: ' + fs.existsSync(landingPath));

  // FIX : essayer plusieurs chemins possibles
  const possiblePaths = [
    path.join(__dirname, 'public/landing.html'),
    path.join(__dirname, 'landing.html'),
    path.join(process.cwd(), 'public/landing.html'),
    path.join(process.cwd(), 'landing.html')
  ];

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      console.log('[ROUTE-/] Landing trouvée à : ' + p);
      return res.sendFile(p);
    }
  }

  // Si vraiment introuvable, on AFFICHE l'erreur explicitement au lieu de rediriger silencieusement
  console.log('[ROUTE-/] ❌ landing.html INTROUVABLE dans tous les chemins testés');
  console.log('[ROUTE-/] __dirname = ' + __dirname);
  console.log('[ROUTE-/] cwd = ' + process.cwd());
  console.log('[ROUTE-/] Files in __dirname: ' + (fs.readdirSync(__dirname).join(', ').substring(0, 200)));
  try { console.log('[ROUTE-/] Files in public: ' + fs.readdirSync(path.join(__dirname, 'public')).join(', ')); } catch(e) { console.log('[ROUTE-/] public/ inaccessible'); }

  // Fallback ultime : rediriger vers login
  return res.redirect('/login.html');
});
app.get('/version', (req, res) => {
  // FIX : on lit le VRAI max_tokens depuis le code source pour pas mentir
  let realMaxTokens = 'inconnu';
  try {
    const selfCode = fs.readFileSync(__filename, 'utf8');
    // Chercher le max_tokens de l'analyse principale (celui après le system prompt trading)
    const m = selfCode.match(/max_tokens:\s*(\d+),\s*\r?\n\s*system:/);
    if (m) realMaxTokens = parseInt(m[1]);
  } catch(e) {}
  res.json({
    version: '2026-05-21-fix-0-trades-v2',
    deployed: 'OK',
    maxTokensReel: realMaxTokens,
    maxTokensAttendu: 3000,
    correct: realMaxTokens === 3000,
    helperGetCandles: typeof getCandles === 'function',
    serverTime: new Date().toISOString()
  });
});

app.get('/app', checkAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/landing.html', (req, res) => {
  // FIX : si user déjà connecté → direct app, pas la landing commerciale
  if (req.session && req.session.userId) {
    return res.redirect('/app');
  }
  res.sendFile(path.join(__dirname, 'public/landing.html'));
});

// FIX : endpoint léger pour que la landing puisse vérifier en JS si l'user est connecté
app.get('/api/me/session-status', (req, res) => {
  res.json({
    connected: !!(req.session && req.session.userId),
    hasSubscription: !!(req.session && req.session.userId)
  });
});
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
  const { email, password, packDemande } = req.body;
  if (!email || !password) return res.json({ error: 'Champs manquants' });
  if (password.length < 6) return res.json({ error: 'Mot de passe trop court (6 min)' });
  try {
    const existing = await db.findOneAsync({ email: email.toLowerCase() });
    if (existing) return res.json({ error: 'Email déjà utilisé' });
    const hash = await bcrypt.hash(password, 10);
    const token = uuidv4();
    // FIX : si packDemande envoyé depuis landing, on l'enregistre en attente de validation admin
    const packValide = ['starter', 'pro', 'elite'].includes((packDemande || '').toLowerCase());
    await db.insertAsync({
      email: email.toLowerCase(), password: hash,
      role: 'user', isVerified: false,
      verifyToken: token, analysisCount: 0,
      analysisMax: 2, subscribed: false,
      banned: false,
      paymentStatus: packValide ? 'pending_payment' : 'pending',
      packDemande: packValide ? packDemande.toLowerCase() : null,
      packDemandeAt: packValide ? new Date() : null,
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
    // FIX multi-comptes : mémoriser le compte MT5 actif en session
    req.session.userMT5AccountId = user.activeMT5AccountId || null;
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
    plan: user.plan || 'free',
    hasPremium: hasPremiumAccess(user),
    paiementEnRetard: isPaiementEnRetard(user),
    paidUntil: user.paidUntil || null,
    mt5: user.mt5 ? {
      connected: true,
      login: user.mt5.login,
      server: user.mt5.server,
      accountType: user.mt5.accountType,
      capital: user.mt5.capital,
      balance: user.mt5.balance,
      credit: user.mt5.credit || 0,
      equity: user.mt5.equity,
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
app.get('/postmortem/pending', checkAuth, checkPremiumPlan, async (req, res) => {
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
app.post('/postmortem/:analysisId', checkAuth, checkPremiumPlan, upload.single('screen'), async (req, res) => {
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
      accountId: analyse.accountId || req.session.userMT5AccountId || null,
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
// ─── GET /analyses/source/:id/statut — statut TP/SL d'une analyse source ──
// Utilisé par le bandeau Setup A+ pour afficher le résultat final du setup
// même si le client l'a vu après coup. L'analyse appartient à un autre user
// donc on ne retourne que feedbackResult (pas les données perso).
app.get('/analyses/source/:id/statut', checkAuth, async (req, res) => {
  try {
    const analyse = await analysesDb.findOneAsync({ _id: req.params.id });
    if (!analyse) return res.json({ statut: null });
    res.json({
      statut: analyse.feedbackResult || null,  // 'tp' | 'sl' | 'pending' | null
      instrument: analyse.instrument || null,
      decision: analyse.decision || null
    });
  } catch(e) { res.json({ statut: null }); }
});

// ─── GET /aplus/:id — récupérer les détails d'un setup A+ pour un user ─────
// Quand un user clique sur le lien email "Voir le setup", on lui retourne
// les détails complets + le LOT RECALCULÉ pour SON capital.
app.get('/aplus/:id', checkAuth, async (req, res) => {
  try {
    const analyse = await analysesDb.findOneAsync({ _id: req.params.id });
    if (!analyse) return res.status(404).json({ error: 'Setup introuvable' });

    const user = await db.findOneAsync({ _id: req.session.userId });
    if (!hasPremiumAccess(user)) {
      return res.status(403).json({ error: 'Plan Pro/Elite requis pour voir ce setup' });
    }

    // Recalculer le lot pour CE user (pas celui du shareur)
    let lots = analyse.lots; // fallback
    let montantRisque = analyse.montantRisque;
    let risquePct = 3;
    if (user.mt5 && user.mt5.capital && analyse.entree && analyse.sl) {
      const score = parseFloat(analyse.score) || 7;
      risquePct = score >= 8 ? 3 : score >= 6 ? 2 : 1;
      const slDist = Math.abs(parseFloat(analyse.entree) - parseFloat(analyse.sl));
      const lotsCalc = calculerLots(parseFloat(user.mt5.capital), risquePct, analyse.slPips, analyse.instrument || '', slDist);
      if (lotsCalc) {
        lots = lotsCalc;
        montantRisque = (parseFloat(user.mt5.capital) * risquePct / 100).toFixed(2);
      }
    }

    res.json({
      _id: analyse._id,
      decision: analyse.decision,
      instrument: analyse.instrument,
      entree: analyse.entree || analyse.entry,
      sl: analyse.sl,
      tp1: analyse.tp1 || analyse.tp,
      tp2: analyse.tp2,
      tp3: analyse.tp3,
      score: analyse.score,
      lots,
      montantRisque,
      risquePct,
      sourceAnalysisId: analyse._id,
      raisonCourte: analyse.raisonCourte || analyse.raison || null,
      statut: analyse.feedbackResult || null,
      hasMT5: !!(user.mt5 && user.mt5.metaApiAccountId)
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

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

app.get('/apprentissage/lecons', checkAuth, checkPremiumPlan, async (req, res) => {
  try {
    const lecons = await leconsDb.findAsync({ userId: req.session.userId });
    lecons.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ count: lecons.length, lecons });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/apprentissage/lecons/:id', checkAuth, checkPremiumPlan, async (req, res) => {
  try {
    await leconsDb.removeAsync({ _id: req.params.id, userId: req.session.userId });
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get('/apprentissage/setups-gagnants', checkAuth, checkPremiumPlan, async (req, res) => {
  try {
    const setups = await setupsGagnantsDb.findAsync({ userId: req.session.userId });
    setups.sort((a, b) => b.profit - a.profit);
    res.json({ count: setups.length, setups: setups.slice(0, 20) });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/apprentissage/setups-gagnants/:id', checkAuth, checkPremiumPlan, async (req, res) => {
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
    // ─── FIX problème 11 : éviter analyses simultanées du même user ─────
    const _userId = req.session.userId;
    if (_userId && _analysisLocks.has(_userId)) {
      const lockTime = _analysisLocks.get(_userId);
      // Lock valide pendant 60s max (au-delà, on considère que l'analyse précédente a planté)
      if (Date.now() - lockTime < 60 * 1000) {
        console.log('[ANALYZE-LOCK] Analyse déjà en cours pour ' + _userId);
        return res.status(429).json({
          error: 'Analyse déjà en cours, attendez la fin avant de relancer',
          retryAfter: 60 - Math.round((Date.now() - lockTime) / 1000)
        });
      }
    }
    if (_userId) _analysisLocks.set(_userId, Date.now());

    // Libérer automatiquement le lock à la fin de la requête (succès ou erreur)
    res.on('finish', () => {
      if (_userId) _analysisLocks.delete(_userId);
    });
    res.on('close', () => {
      if (_userId) _analysisLocks.delete(_userId);
    });

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
        return res.json({ error: 'paiement_en_retard', message: '⚠️ Abonnement expiré — Contacte @bigtazz pour renouveler ton accès.' });
      }
      if (!canAnalyze(user)) {
        allFiles.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });
        return res.json({ limitReached: true, redirect: '/abonnement.html' });
      }
    }

    if (allFiles.length === 0) return res.status(400).json({ error: 'Aucune image reçue' });

    let capital = parseFloat(req.body.capital) || 0;
    // Fallback : si capital vide (MT5 connecté), utiliser mt5.capital en DB
    if (capital <= 0 && user.mt5 && user.mt5.capital) {
      capital = parseFloat(user.mt5.capital) || 0;
    }
    const content = [];
    const tfNames = { imageH1: 'H1', imageM30: 'M30', imageM15: 'M15', imageM5: 'M5', imageM1: 'M1' };
    const tfOrder = ['imageH1', 'imageM30', 'imageM15', 'imageM5', 'imageM1'];

    // FIX PERFS : compresser les images > 500KB pour accélérer Claude
    // Claude analyse plus vite des images de taille modérée
    let sharp;
    try { sharp = require('sharp'); } catch(e) { sharp = null; }

    for (const tfKey of tfOrder) {
      const file = files[tfKey]?.[0];
      if (file) {
        let imageData = fs.readFileSync(file.path);
        let mimeTypeFinal = file.mimetype || 'image/png'; // type réel par défaut

        // Si > 500KB et sharp dispo, on redimensionne à 1280px max
        if (sharp && imageData.length > 500 * 1024) {
          try {
            const tStart = Date.now();
            imageData = await sharp(imageData)
              .resize({ width: 1280, height: 1280, fit: 'inside', withoutEnlargement: true })
              .jpeg({ quality: 85, mozjpeg: true })
              .toBuffer();
            mimeTypeFinal = 'image/jpeg'; // seulement si compression réussie
            console.log('[ANALYZE-PERF] Image ' + tfKey + ' compressée en ' + (Date.now()-tStart) + 'ms (taille finale: ' + Math.round(imageData.length/1024) + 'KB)');
          } catch(e) {
            console.log('[ANALYZE-PERF] Compression échouée pour ' + tfKey + ': ' + e.message);
            imageData = fs.readFileSync(file.path);
            // mimeTypeFinal reste celui du fichier original
          }
        }

        content.push({
          type: 'image',
          source: { type: 'base64', media_type: mimeTypeFinal, data: imageData.toString('base64') }
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
- NE PAS TRADER sauf si : (1) cassure NETTE du range asiatique avec forte bougie + (2) score >= 7 + (3) confluence CRT + ICT claire (OPTION B : plus permissif qu'avant qui exigeait 8)
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
    const blocLecons = await getLeconsPourPrompt(req.session.userId, req.session.userMT5AccountId);

    // 🏆 Setups gagnants précédents (patterns à reproduire)
    const blocSetupsGagnants = await getBlocSetupsGagnants(req.session.userId, req.body.instrument || 'XAUUSD', req.session.userMT5AccountId);

    // 🧠 PATTERN D'ERREURS PERSONNALISÉ (Pro/Elite uniquement)
    let blocPatternErreurs = '';
    try {
      const userPourPattern = await db.findOneAsync({ _id: req.session.userId });
      const pattern = await getPatternErreursPersonnalise(req.session.userId, userPourPattern);
      if (pattern) blocPatternErreurs = '\n═══ PATTERN PERSONNEL ═══\n' + pattern + '\n';
    } catch(e) { /* silent : pas Pro/Elite ou pas assez de data */ }

    // 🔍 OB/FVG détectés algorithmiquement (data objective)
    // FIX VITESSE : timeout 25s sur getBlocOBFVG. Si MetaApi traîne, analyse sur images.
    let blocOBFVG = '';
    try {
      blocOBFVG = await Promise.race([
        getBlocOBFVG(req.session.userId, req.body.instrument || 'XAUUSD'),
        new Promise((resolve) => setTimeout(() => { console.log('[ANALYZE-PERF] getBlocOBFVG timeout 25s - images seules'); resolve(''); }, 25000))
      ]);
    } catch(e) { console.log('[ANALYZE-PERF] getBlocOBFVG err: ' + e.message); blocOBFVG = ''; }

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

    // FIX : on NE bloque PLUS automatiquement sur un conflit contextuel.
    // Avant : NE PAS TRADER direct sans demander à l'IA (bloquait trop, surtout en range).
    // Maintenant : on signale juste le conflit à l'IA dans le prompt, elle décide.
    let conflitWarning = '';
    if (conflitDetecte) {
      console.log('[CONFLIT-CONTEXTUEL] ' + raisonConflit + ' — signalé à l IA (pas de blocage auto)');
      conflitWarning = '\n⚠️ NOTE SERVEUR : ' + raisonConflit + '. Sois prudent mais analyse quand même les images.';
    }

    content.push({
      type: 'text',
      text: `═══ MÉTHODE OBLIGATOIRE — SÉLECTION INTELLIGENTE DU MEILLEUR SETUP ═══
Tu testes MENTALEMENT plusieurs concepts ICT/SMC et tu retournes UNIQUEMENT LE MEILLEUR (score le + élevé).

CONCEPTS À ÉVALUER (donne un score 0-10 à chacun) :
 1. CRT_KASPER — range asiat + faux breakout + close opposé (meilleur début Londres)
 2. OTE_FIBO — prix dans 61.8-78.6% retracement + tendance alignée (meilleur en tendance)
 3. AMD — Accumulation→Manipulation→Distribution (meilleur Londres/NY)
 4. SWEEP_REVERSAL — sweep liquidité récent + bougie réversal
 5. SILVER_BULLET — 10h-11h NY uniquement (fenêtre stricte)
 6. VOLUME_SPIKE — volume 2x+ moyenne sur cassure (confirme breakouts)
 7. POC_RETEST — prix retest le Point of Control (meilleur en range)
 8. ORDER_BLOCK_H1 — OB qualité HIGH non mitigé (meilleur sur retracement)

⚠️ DONNÉES MANQUANTES : si tu n'as pas le volume sur les images (VOLUME_SPIKE)
ou pas de profil volumétrique (POC_RETEST), NE mets PAS un score bas par défaut.
Marque ces concepts "non évaluable" et juge sur les 6 autres concepts visibles.
Ne pénalise JAMAIS le score global juste parce qu'un concept est non évaluable.

→ Choisis le concept au score le + élevé.

═══ LOGIQUE DE CONFLUENCE (IMPORTANT) ═══
Étape 1 : Si UN concept seul a score >= 6 → trade dessus directement.

Étape 2 : Si AUCUN concept seul n'atteint 6, cherche une CONFLUENCE :
- Identifie 2 ou 3 concepts COMPATIBLES qui ont chacun score >= 4
- Ils doivent pointer dans le MÊME sens (tous BUY ou tous SELL)
- Ils doivent viser le MÊME niveau de prix (zone proche, ex ±8$ sur XAUUSD)
- Combinaisons VALIDES : OTE_FIBO+ORDER_BLOCK_H1 / SWEEP_REVERSAL+CRT_KASPER /
  AMD+VOLUME_SPIKE / POC_RETEST+OTE_FIBO / ORDER_BLOCK_H1+SWEEP_REVERSAL
- Combinaisons INTERDITES : SILVER_BULLET+CRT_KASPER (heures opposées),
  ou tout concept en contradiction de direction.

Calcul du score combiné en confluence :
  score_combiné = score du meilleur concept + 1 par concept compatible aligné supplémentaire
  Exemple : OTE_FIBO(5) + ORDER_BLOCK_H1(5) alignés même zone → 5 + 1 = 6 → TRADE VALIDE
  Exemple : OTE_FIBO(5) + ORDER_BLOCK(4) + SWEEP(4) alignés → 5 + 2 = 7 → TRADE A

Étape 3 : Si score_combiné >= 6 → TRADE (indique les concepts dans "conceptUtilise" séparés par +).
Étape 4 : Si même en confluence le score reste < 6 → "NE PAS TRADER".

RÈGLE D'OR : la confluence sert à détecter de VRAIS setups multi-concepts,
PAS à forcer un trade. Si les concepts ne sont pas réellement alignés au même
niveau et même sens, NE COMBINE PAS — dis "NE PAS TRADER".

→ Renseigne "conceptUtilise" et "conceptsTestes" dans le JSON
→ Pour le scoring final tu utilises le score du concept gagnant OU le score combiné

═══ FORMAT PRIX OBLIGATOIRE PAR INSTRUMENT ═══
- XAUUSD/Gold : 2 décimales (ex 4710.50)
- EURUSD, GBPUSD, AUDUSD, NZDUSD : 5 décimales (ex 1.08456)
- USDJPY, EURJPY, GBPJPY : 3 décimales (ex 154.235)
- XAGUSD : 3 décimales | BTCUSD : 1 décimale | ETHUSD : 2 décimales
- NAS100, US30, GER40 : 1 décimale | US500 : 2 décimales

DISTANCE SL MINIMUM par instrument (trade rejeté serveur si non respecté) :
- XAUUSD : 1.5\$ min (CRT Kasper M1) ou 3\$ (autres méthodes)
- EURUSD/GBPUSD/AUDUSD/NZDUSD : 0.0010 (10 pips)
- USDJPY/JPY : 0.10 (10 pips)
- BTC : 150\$ | ETH : 10\$ | NAS100/US30 : 20 points

VALIDATION TP/SL OBLIGATOIRE :
- TP1, TP2, TP3 STRICTEMENT différents de l'entrée
- Distance TP-entrée >= 0.8x distance SL (sinon trade rejeté)
- Pour BUY : TP1 < TP2 < TP3 et tous au-dessus de l'entrée
- Pour SELL : TP1 > TP2 > TP3 et tous en-dessous de l'entrée

═══ TP INTELLIGENTS — basés sur les NIVEAUX MARCHÉ réels ═══
TES TP ne sont PAS aléatoires. Tu les places sur les VRAIS niveaux :
- TP1 = niveau proche (FVG opposée / OB intermédiaire / swing M5) → RR 1:1.5 à 1:2.5
- TP2 = niveau structurel (Fibo 127.2% / equal H-L) → RR 1:3 à 1:5
- TP3 = niveau MAJEUR (DOL / Asian range opposé / Fibo 161.8%) → RR 1:5 à 1:10

Tu es un trader ICT/Smart Money expérimenté qui aide un trader sur ${req.body.instrument || 'XAUUSD'}.${capital ? ` Capital: $${capital}.` : ''}

${blocLecons}${blocSetupsGagnants}${blocPatternErreurs}${blocOBFVG}${blocIndicateurs}

CONTEXTE : ${sessionWarning}${conflitWarning}
SESSION : ${sessionActive}

═══════════════════════════════════════════════════════════════
🎯 TA MISSION
═══════════════════════════════════════════════════════════════
Analyse les ${nbTF} graphique(s) fournis (${tfDisponibles}) et donne UN signal de qualité OU dis "NE PAS TRADER".

Tu reçois aussi des données objectives calculées sur les vraies bougies MetaAPI :
- Indicateurs RSI/MA (ci-dessus dans 📊 INDICATEURS TECHNIQUES)
- OB/FVG algorithmiques (ci-dessus dans 🔍 NIVEAUX TECHNIQUES)
- Tes leçons passées et setups gagnants

⚠️ RÈGLES RSI STRICTES (serveur les vérifiera après toi) :
- RSI M15 > 75 → NE PAS TRADER en BUY (surachat, momentum baissier imminent)
- RSI M15 < 25 → NE PAS TRADER en SELL (survente, rebond probable)
- RSI M15 > 70 ET BUY → score max 6/10 (condition dégradée)
- RSI M15 < 30 ET SELL → score max 6/10 (condition dégradée)
- RSI H1 > 70 ET BUY → score réduit de 1 point (momentum H1 épuisé)
- RSI H1 < 30 ET SELL → score réduit de 1 point (momentum H1 épuisé)
- RSI D1 > 75 ET BUY → signale-le dans raisonsContre même si tu trades
Si le prix est très loin sous/sur MA50 → mouvement épuisé, sois prudent.

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

Réponds UNIQUEMENT avec un JSON valide, COMPACT, sans texte avant ou après, sans backticks.
IMPORTANT : sois CONCIS dans les champs texte (raisons en max 10 mots) pour que le JSON soit COMPLET et bien fermé.

{
  "decision": "BUY" ou "SELL" ou "NE PAS TRADER",
  "conceptUtilise": "<CRT_KASPER | OTE_FIBO | AMD | SWEEP_REVERSAL | SILVER_BULLET | VOLUME_SPIKE | POC_RETEST | ORDER_BLOCK_H1 | NONE>",
  "conceptsTestes": [
    {"nom":"<concept1>","score":<0-10>,"raison":"<max 10 mots>"},
    {"nom":"<concept2>","score":<0-10>,"raison":"<max 10 mots>"}
  ],
  "tp1Source": "<source: 'FVG opposée' / 'Swing M5' / 'Fibo 127.2%' / 'Equal Highs' etc.>",
  "tp2Source": "<source niveau structurel>",
  "tp3Source": "<source niveau majeur: 'DOL Asian High' / 'Fibo 161.8%' etc.>",
  "volumeConfirmation": "<OUI/NON — y a-t-il un volume spike confirmant la direction ?>",
  "session": "${sessionActive}",
  "sessionImpact": "<comment la session influence ce signal>",
  "confiance": "XX%",
  "score": <0 à 10>,
  "tendance": "<M30>",
  "tendanceD1": "<D1 — OBLIGATOIRE : BULLISH | BEARISH | RANGE | Non disponible>",
  "tendanceH1": "<H1 ou 'Non fourni'>",
  "tendanceM15": "<M15 ou 'Non fourni'>",
  "tendanceM5": "<M5 ou 'Non fourni'>",
  "tendanceM1": "<M1 ou 'Non fourni'>",
  "confluence": "<alignement TF>",
  "entree": <NOMBRE UNIQUE OBLIGATOIRE — ex: 4558.50 — JAMAIS de zone "4558-4562", JAMAIS de texte, JAMAIS de plage>,
  "entreeType": "LIMIT" ou "MARKET",
  "entreeLevel": "<TEXTE descriptif uniquement ici, ex: 'Retest FVG bullish créée par displacement depuis 4528' ou 'Retest OB H1 4675'>",
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
  "capital": ${capital || 0},

  "raisonsPour": ["<2-3 raisons pour ce trade — courtes, max 100 char chacune>"],
  "raisonsContre": ["<1-3 risques pour ce trade — sois honnête mais ce n'est pas obligatoire d'en trouver 3>"],
  "scenarioOptimiste": "<si tout va bien, où va le prix ? niveau cible>",
  "scenarioRealiste": "<scénario le plus probable>",
  "scenarioPessimiste": "<si ça foire, comment ?>",
  "validiteMinutes": <durée en minutes après laquelle ce setup expire (typique 15-60 min)>,
  "raisonCourte": "<résumé en 1 phrase de l'essence du setup, max 100 caractères>"
}

⚠️ Le champ "rsiUtilise" est OBLIGATOIRE — il prouve que tu as bien lu les indicateurs.
Les autres champs (raisonsPour, raisonsContre, scénarios, validiteMinutes) sont informatifs pour aider le trader à comprendre.`
    });

    // FIX PERFS : logger le temps pour traquer la lenteur
    const _tStart = Date.now();
    console.log('[ANALYZE-PERF] Appel Claude début... (images: ' + allFiles.length + ', prompt size: ' + JSON.stringify(content).length + ' chars)');

    // FIX VITESSE : Haiku 4.5 = 3-4x plus rapide que Sonnet, parfait pour ICT/SMC
    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 3000,
      system: 'Tu es un assistant trading expert ICT/SMC. Tu utilises systematiquement les concepts: Draw on Liquidity, Premium/Discount, Market Structure Shift, kill zones, Order Block validation. Tu reponds UNIQUEMENT avec du JSON valide, sans aucun texte avant ou apres, sans backticks, sans markdown. Juste le JSON brut commencant par { et finissant par }.',
      messages: [{ role: 'user', content }]
    });

    const _tEnd = Date.now();
    const _tDur = ((_tEnd - _tStart) / 1000).toFixed(1);
    console.log('[ANALYZE-PERF] Claude répondu en ' + _tDur + 's (tokens: ' + (response.usage?.output_tokens || '?') + '/2500)');

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
          let fixed = clean
            .replace(/,\s*}/g, '}')                     // trailing comma object
            .replace(/,\s*]/g, ']')                     // trailing comma array
            .replace(/:\s*undefined/g, ':null')         // undefined → null
            .replace(/([{,]\s*)(\w+)\s*:/g, '$1"$2":'); // cles sans guillemets

          try {
            parsed = JSON.parse(fixed);
          } catch(e2) {
            // Strategie 5 : reparer les virgules MANQUANTES dans les tableaux
            // Pattern : "valeur"\n  "valeur" ou "valeur" "valeur" → ajout de virgule
            fixed = fixed
              .replace(/"\s*\n\s*"/g, '",\n"')        // strings sur lignes différentes
              .replace(/"\s+"/g, '","')                 // strings collées avec espace
              .replace(/}\s*\n\s*{/g, '},\n{')        // objets sur lignes différentes
              .replace(/]\s*\n\s*\[/g, '],\n[')      // arrays sur lignes différentes
              .replace(/(\d)\s*\n\s*"/g, '$1,\n"')   // nombre suivi de string
              .replace(/(\d)\s+(\d)/g, '$1,$2')       // 2 nombres collés
              .replace(/}\s+"/g, '},"')                 // } suivi de string
              .replace(/]\s+"/g, '],"');                // ] suivi de string

            try {
              parsed = JSON.parse(fixed);
              console.log('[PARSING] JSON repare via strategie 5 (virgules manquantes)');
            } catch(e3) {
              // Strategie 6 : extraction manuelle des champs critiques au regex
              // Si tout echoue, on construit un objet minimal pour pas tout casser
              console.log('[PARSING] Toutes strategies echouees. Extraction au regex de secours.');
              parsed = {};
              const extractField = (name, isNumber = false) => {
                const re = new RegExp('"' + name + '"\\s*:\\s*' + (isNumber ? '([\\d.\\-]+)' : '"([^"]*)"'));
                const m = clean.match(re);
                if (m) parsed[name] = isNumber ? parseFloat(m[1]) : m[1];
              };
              extractField('decision');
              extractField('entree', true);
              extractField('sl', true);
              extractField('tp', true);
              extractField('tp1', true);
              extractField('tp2', true);
              extractField('tp3', true);
              extractField('score', true);
              extractField('confidence', true);
              extractField('justification');
              extractField('lots', true);
              extractField('contexte');
              // Si on n'a pas pu extraire au moins decision + entree, on relance l'erreur
              if (!parsed.decision || (parsed.decision !== 'NE PAS TRADER' && (!parsed.entree || !parsed.sl))) {
                throw new Error('Extraction regex incomplete - JSON IA trop corrompu');
              }
              parsed.decision = parsed.decision || 'NE PAS TRADER';
              parsed.justification = parsed.justification || 'Reponse IA partiellement corrompue, donnees extraites au regex';
            }
          }
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
        const score = parseFloat(parsed.score) || 7;
        const inst = (parsed.instrument || 'XAU').toUpperCase();
        const decimales = inst.match(/JPY/) ? 3 : (inst.match(/EUR|GBP|AUD|NZD|CHF|CAD/) && !inst.match(/JPY/) ? 5 : 2);
        parsed.sl = +slCorrige.toFixed(decimales);

        // Tenter TPs intelligents basés sur niveaux marché réels
        let tpsIntel = null;
        try {
          const ictCache = global._ictCache && global._ictCache[req.session.userId];
          const analyseICT = ictCache?.analyse || null;
          let pocData = null;
          try {
            const md = await fetchAllMarketData(req.session.userId, inst);
            if (md && md.candlesM15) pocData = calculerPOC(md.candlesM15, 20);
          } catch(e) {}
          tpsIntel = calculerTPsIntelligents(parsed.decision, entree, slCorrige, analyseICT, pocData);
        } catch(e) { console.log('[TP-INTEL]', e.message); }

        if (tpsIntel && tpsIntel.tp1 && tpsIntel.tp2 && tpsIntel.tp3) {
          // Niveaux marché trouvés
          parsed.tp1 = tpsIntel.tp1; parsed.tp2 = tpsIntel.tp2; parsed.tp3 = tpsIntel.tp3;
          parsed.tp1Source = tpsIntel.tp1Source; parsed.tp2Source = tpsIntel.tp2Source; parsed.tp3Source = tpsIntel.tp3Source;
          parsed.tp1RR = tpsIntel.tp1RR; parsed.tp2RR = tpsIntel.tp2RR; parsed.tp3RR = tpsIntel.tp3RR;
          parsed.slPips = Math.round(dist * 100) / 100;
          parsed.tp1Pips = Math.round(Math.abs(tpsIntel.tp1 - entree) * 100) / 100;
          parsed.tp2Pips = Math.round(Math.abs(tpsIntel.tp2 - entree) * 100) / 100;
          parsed.tp3Pips = Math.round(Math.abs(tpsIntel.tp3 - entree) * 100) / 100;
          parsed.tpsCalcule = 'INTELLIGENT';
          console.log('[TP-INTEL] ' + tpsIntel.tp1Source + ' R' + tpsIntel.tp1RR + ' | ' + tpsIntel.tp2Source + ' R' + tpsIntel.tp2RR + ' | ' + tpsIntel.tp3Source + ' R' + tpsIntel.tp3RR);
        } else {
          // Fallback RR adaptatifs ATTRACTIFS
          let rr1, rr2, rr3;
          if (score >= 9) { rr1 = 2.0; rr2 = 4.0; rr3 = 8.0; }
          else if (score >= 7) { rr1 = 1.5; rr2 = 3.0; rr3 = 5.0; }
          else { rr1 = 1.0; rr2 = 2.0; rr3 = 3.0; }
          const tp1 = isBuy ? entree + dist * rr1 : entree - dist * rr1;
          const tp2 = isBuy ? entree + dist * rr2 : entree - dist * rr2;
          const tp3 = isBuy ? entree + dist * rr3 : entree - dist * rr3;
          parsed.tp1 = +tp1.toFixed(decimales);
          parsed.tp2 = +tp2.toFixed(decimales);
          parsed.tp3 = +tp3.toFixed(decimales);
          parsed.tp1RR = rr1; parsed.tp2RR = rr2; parsed.tp3RR = rr3;
          parsed.slPips = Math.round(dist * 100) / 100;
          parsed.tp1Pips = Math.round(dist * rr1 * 100) / 100;
          parsed.tp2Pips = Math.round(dist * rr2 * 100) / 100;
          parsed.tp3Pips = Math.round(dist * rr3 * 100) / 100;
          parsed.tpsCalcule = 'FALLBACK_RR';
        }
      }
    }

    // ═══ MODE DEBUG : sauvegarder l'état initial AVANT les garde-fous ═══
    // Permet de comparer ce que l'IA a vraiment dit vs ce que les filtres ont produit
    parsed.decisionInitiale = parsed.decision;
    parsed.scoreInitial = parsed.score;

    // ─── VALIDATION ENTREE = NOMBRE PUR (sinon trade annulé) ────
    // Bug constaté : l'IA mettait parfois "4558-4562 (retest FVG ...)" dans entree
    // au lieu d'un nombre. Résultat : SL distance fausse, MT5 confus.
    // → On vérifie que entree est un nombre simple.
    if (parsed.decision !== 'NE PAS TRADER' && parsed.entree !== undefined && parsed.entree !== null) {
      const entreeStr = String(parsed.entree).trim();
      const entreeNum = parseFloat(entreeStr);
      // Doit être un nombre valide ET la string ne doit pas contenir d'autres chiffres
      // ex: "4558" → ok, "4558.50" → ok, "4558-4562" → KO, "4558 (retest...)" → KO
      const matchPur = /^-?\d+(\.\d+)?$/.test(entreeStr);
      if (isNaN(entreeNum) || entreeNum <= 0 || !matchPur) {
        console.log('[ENTREE-INVALIDE] L\'IA a retourné une entree non numérique : "' + entreeStr + '" → trade annulé');
        // Si entreeLevel est vide, on déplace le contenu d'entree dedans pour ne pas perdre l'info
        if (!parsed.entreeLevel || parsed.entreeLevel.trim() === '') {
          parsed.entreeLevel = entreeStr;
        }
        parsed.decision = 'NE PAS TRADER';
        parsed.entreeInvalideAlerte = 'Entree non numerique fournie par IA : "' + entreeStr.substring(0, 80) + '" — trade annulé pour sécurité';
        parsed.entree = null;
      } else {
        // Normaliser : décimales selon instrument
        // FIX : toFixed(2) cassait EURUSD (1.08456 → 1.08), on garde la précision de l'IA
        const _instNorm = (parsed.instrument || 'XAU').toUpperCase();
        const _dec = _instNorm.match(/JPY/) ? 3 :
                     (_instNorm.match(/EUR|GBP|AUD|NZD|CHF|CAD/) ? 5 :
                     (_instNorm.match(/XAU|XAG|OIL|WTI/) ? 2 : 2));
        parsed.entree = parseFloat(entreeNum.toFixed(_dec));
      }
    }

    // ─── GARDE SCORE MINIMUM 7 (objectif WR 60%) ──────────────────
    // OPTION B : Score min 6 (au lieu de 7) — sauf si contre tendance D1
    // On accepte les setups corrects (6+) tant qu'ils ne vont pas contre D1
    const d1Pour = (parsed.tendanceD1 || '').toUpperCase();
    const isBuyD1 = parsed.decision === 'BUY';
    const contreD1 = (isBuyD1 && d1Pour === 'BEARISH') || (!isBuyD1 && d1Pour === 'BULLISH');
    const scoreMinRequis = contreD1 ? 7 : 6;
    if (parsed.decision !== 'NE PAS TRADER' && (parsed.score || 0) < scoreMinRequis) {
      console.log('[SCORE-GUARD] Score ' + parsed.score + ' < ' + scoreMinRequis + (contreD1 ? ' (contre D1)' : '') + ' → NE PAS TRADER');
      parsed.decision = 'NE PAS TRADER';
      parsed.scoreGuardAlerte = 'Score trop faible (' + parsed.score + '/10) — minimum requis : 7/10 pour viser WR 60%';
    }

    // ─── VALIDATION SL/TP = NOMBRES PURS ───────────────────────
    // Même protection que pour entree : SL/TP doivent être des nombres
    if (parsed.decision !== 'NE PAS TRADER') {
      const champsNum = ['sl', 'tp1', 'tp2', 'tp3'];
      for (const champ of champsNum) {
        if (parsed[champ] === undefined || parsed[champ] === null || parsed[champ] === '') continue;
        const str = String(parsed[champ]).trim();
        const num = parseFloat(str);
        const pur = /^-?\d+(\.\d+)?$/.test(str);
        if (isNaN(num) || !pur) {
          console.log('[NUM-INVALIDE] ' + champ + ' non numérique : "' + str + '" → annulé');
          parsed.decision = 'NE PAS TRADER';
          parsed.numInvalideAlerte = champ + ' = "' + str.substring(0, 60) + '" non numérique';
          break;
        } else {
          // FIX : décimales selon instrument (EURUSD a besoin de 5 décimales)
          const _instSL = (parsed.instrument || 'XAU').toUpperCase();
          const _decSL = _instSL.match(/JPY/) ? 3 :
                         (_instSL.match(/EUR|GBP|AUD|NZD|CHF|CAD/) ? 5 :
                         (_instSL.match(/XAU|XAG|OIL|WTI/) ? 2 : 2));
          parsed[champ] = parseFloat(num.toFixed(_decSL));
        }
      }
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
      // BLOCK 3 : RSI M15 extrême — lit le RSI RÉEL depuis le cache MetaAPI
      // FIX : l'IA ne retourne jamais rsiM15 dans son JSON → le bloc était mort
      let rsiM15 = 0;
      try {
        const cacheIct = global._ictCache && global._ictCache[req.session.userId];
        if (cacheIct && cacheIct.rsiM15 != null) {
          rsiM15 = parseFloat(cacheIct.rsiM15);
        } else {
          rsiM15 = parseFloat(parsed.rsi || parsed.rsiM15 || 0);
        }
      } catch(_rsi) { rsiM15 = 0; }
      if (rsiM15 > 0) {
        if (isBuy && rsiM15 > 78) hardBlocks.push('RSI M15 ' + rsiM15.toFixed(1) + ' > 78 (surachat extrême) avec BUY');
        if (!isBuy && rsiM15 < 22) hardBlocks.push('RSI M15 ' + rsiM15.toFixed(1) + ' < 22 (survente extrême) avec SELL');
      }

      // OPTION B : on annule SEULEMENT si 2+ hardBlocks (avant : 1 suffisait)
      // 1 seul block = warning + score réduit (le trader décide)
      if (hardBlocks.length >= 2) {
        console.log('[HARD-BLOCK] ' + parsed.decision + ' annulé (' + hardBlocks.length + ' blocks) : ' + hardBlocks.join(' | '));
        parsed.decision = 'NE PAS TRADER';
        parsed.hardBlockAlerte = 'Trade annulé : ' + hardBlocks.length + ' blocks détectés (' + hardBlocks.join(' | ') + ')';
      } else if (hardBlocks.length === 1) {
        console.log('[HARD-BLOCK-WARN] ' + parsed.decision + ' : 1 warning (' + hardBlocks[0] + ') — score réduit');
        parsed.score = Math.max((parsed.score || 7) - 1, 6);
        parsed.hardBlockAlerte = '⚠️ Attention : ' + hardBlocks[0] + ' (score réduit à ' + parsed.score + ')';
      }
    }

    // ─── COHÉRENCE TENDANCE D1 IA vs DÉCISION ────────────────────
    // L'IA retourne tendanceD1 dans son JSON — on vérifie qu'elle ne
    // propose pas un trade contraire à ce qu'elle a elle-même identifié.
    // Ex : tendanceD1=BEARISH mais decision=BUY → score réduit ou annulation.
    if (parsed.decision === 'BUY' || parsed.decision === 'SELL') {
      const d1IA = (parsed.tendanceD1 || '').toUpperCase();
      const isBuyD1 = parsed.decision === 'BUY';
      const d1ContreSignal = (isBuyD1 && d1IA === 'BEARISH') || (!isBuyD1 && d1IA === 'BULLISH');
      if (d1ContreSignal) {
        // Vérifier si MSS D1 récent dans les champs IA (override possible)
        const structEvt = (parsed.structureEvent || '').toUpperCase();
        const mssD1Aligne = (isBuyD1 && structEvt === 'MSS_BULLISH') || (!isBuyD1 && structEvt === 'MSS_BEARISH');
        if (!mssD1Aligne) {
          const scoreActuel = parseFloat(parsed.score) || 0;
          if (scoreActuel >= 9) {
            // Score très élevé = setup fort, juste réduire
            parsed.score = Math.min(parsed.score, 7);
            parsed.protectionsAlertes = (parsed.protectionsAlertes ? parsed.protectionsAlertes + ' | ' : '') +
              '⚠️ Trade contre tendance D1 ' + d1IA + ' (IA le confirme elle-même) — score réduit à ' + parsed.score;
          } else {
            // OPTION B : score moyen contre D1 → score réduit MAIS pas annulé direct
            // L'IA peut quand même proposer si score reste >= 6 après réduction
            const oldScore = parsed.score || 6;
            const newScore = Math.max(oldScore - 1, 5);
            parsed.score = newScore;
            if (newScore >= 6) {
              // Score acceptable : on garde le trade mais avec warning
              parsed.protectionsAlertes = (parsed.protectionsAlertes ? parsed.protectionsAlertes + ' | ' : '') +
                '⚠️ Trade contre D1 ' + d1IA + ' (score réduit ' + oldScore + ' → ' + newScore + ') — sois prudent';
            } else {
              // Score trop bas : annulation
              parsed.decision = 'NE PAS TRADER';
              parsed.protectionsAlertes = (parsed.protectionsAlertes ? parsed.protectionsAlertes + ' | ' : '') +
                '🚫 ' + (isBuyD1 ? 'BUY' : 'SELL') + ' contre D1 ' + d1IA + ', score trop bas après réduction (' + newScore + ')';
            }
          }
          console.log('[D1-COHERENCE] ' + (isBuyD1 ? 'BUY' : 'SELL') + ' vs D1=' + d1IA + ' score=' + scoreActuel + ' → ' + parsed.decision);
        }
      }
    }

    // ─── ANTI-PIÈGE RANGE ASIATIQUE (vérification post-IA) ────
    parsed = verifierPiegeRangeAsiatique(parsed);

    // ─── RÉAJUSTEMENT AUTO DE L'ENTRÉE (vs prix actuel MetaAPI) ───
    parsed = await reajusterEntreeSiNecessaire(parsed, req.session.userId);

    // ─── PROTECTIONS AVANCÉES (RSI extrême + mouvement épuisé + R:R réel) ───
    parsed = await verifierProtectionsAvancees(parsed, req.session.userId);

    // ─── CALCUL LOTS CÔTÉ SERVEUR (avec modes profit) ──────────
    if (capital && parsed.slPips && parsed.decision !== 'NE PAS TRADER') {
      const score = parsed.score || 0;

      // Récupérer le mode du user (NORMAL / VAGUE_VERTE / SURF / VIGILANCE / PRESERVATION)
      // pour ajuster le risque selon le score
      const facteurInfo = await getFacteurRisque(req.session.userId, capital);
      parsed.modeRisque = facteurInfo.mode || 'NORMAL';
      parsed.modeAlerte = facteurInfo.alerte || null;
      parsed.gainPct = facteurInfo.gainPct || null;
      parsed.winRate7j = facteurInfo.winRate7j || null;

      // Risque de base par score (toujours sur le capital total — sécurisé)
      let risquePct = score >= 8 ? 3 : score >= 6 ? 2 : 1;

      // 🟢 BONUS VAGUE VERTE / SURF : risque supplémentaire sur la part de GAINS uniquement
      // Le capital initial reste protégé à 3% max. Le bonus s'ajoute sur les gains réalisés.
      let bonusRisqueDollar = 0;
      if (facteurInfo.gainCumule && facteurInfo.gainCumule > 0) {
        if (facteurInfo.mode === 'SURF' && score >= 9) {
          // Score 10 : 7% des gains, Score 9 : 5% des gains
          const pctBonus = score >= 10 ? (facteurInfo.bonusPctScore10 || 7) : (facteurInfo.bonusPctScore9 || 5);
          bonusRisqueDollar = (facteurInfo.gainCumule * pctBonus / 100);
        } else if (facteurInfo.mode === 'VAGUE_VERTE' && score >= 9) {
          // Score 10 : 5% des gains, Score 9 : 4% des gains
          const pctBonus = score >= 10 ? (facteurInfo.bonusPctScore10 || 5) : (facteurInfo.bonusPctScore9 || 4);
          bonusRisqueDollar = (facteurInfo.gainCumule * pctBonus / 100);
        }
      }

      const montantBase = capital * risquePct / 100;
      const montantTotal = montantBase + bonusRisqueDollar;

      // CAP ABSOLU : on ne dépasse jamais 5% du capital total (sécurité ultime)
      const capAbsolu = capital * 0.05;
      const montantFinal = Math.min(montantTotal, capAbsolu);

      // Recalculer le pct effectif pour l'affichage
      const pctEffectif = (montantFinal / capital) * 100;
      parsed.risquePct = +pctEffectif.toFixed(2);
      parsed.risqueBase = +risquePct;
      parsed.risqueBonusDollar = +bonusRisqueDollar.toFixed(2);
      parsed.gainCumule = facteurInfo.gainCumule || 0;

      // FIX BUG 5 : utiliser la distance directe |entrée - SL| en dollars
      let slDistanceDollars = null;
      if (parsed.entree && parsed.sl) {
        const distDirect = Math.abs(parseFloat(parsed.entree) - parseFloat(parsed.sl));
        if (distDirect > 0 && !isNaN(distDirect)) slDistanceDollars = distDirect;
      }
      // Calculer lot avec le pourcentage EFFECTIF (qui inclut le bonus mode profit)
      parsed.lots = calculerLots(capital, pctEffectif, parsed.slPips, parsed.instrument || '', slDistanceDollars);
      parsed.montantRisque = montantFinal.toFixed(2);

      // ─── LOT DYNAMIQUE (anti-drawdown / anti-tilt) — APPLIQUE SI FACTEUR < 1 ──
      const facteur = facteurInfo.facteur;
      const alerte = facteurInfo.alerte;
      if (facteur < 1 && parsed.lots) {
        const lotsOriginaux = parseFloat(parsed.lots);
        parsed.lots = Math.max(0.01, Math.round(lotsOriginaux * facteur * 100) / 100).toFixed(2);
        parsed.montantRisque = (parseFloat(parsed.montantRisque) * facteur).toFixed(2);
        parsed.lotDynamiqueAlerte = alerte;
        console.log('[LOT-DYNAMIQUE] User ' + req.session.userId + ' : ' + lotsOriginaux + ' → ' + parsed.lots + ' (' + alerte + ')');
      }
    }

    // Fallback tendances toujours définies (évite undefined frontend)
    parsed.tendanceServerD1 = parsed.tendanceServerD1 || parsed.tendanceD1 || 'INDISPONIBLE';
    parsed.tendanceServerH1 = parsed.tendanceServerH1 || parsed.tendanceH1 || 'INDISPONIBLE';
    parsed.tendanceServerM30 = parsed.tendanceServerM30 || parsed.tendance || 'INDISPONIBLE';
    parsed.tendanceConfidenceD1 = parsed.tendanceConfidenceD1 || 0;
    parsed.tendanceConfidenceH1 = parsed.tendanceConfidenceH1 || 0;
    parsed.tendanceConfidenceM30 = parsed.tendanceConfidenceM30 || 0;

    // Validation TP/SL stricte (anti-bug "TP = entrée" sur EURUSD/JPY)
    if (parsed.decision !== 'NE PAS TRADER' && parsed.entree && parsed.sl) {
      const ent = parseFloat(parsed.entree);
      const slN = parseFloat(parsed.sl);
      const distSL = Math.abs(ent - slN);
      const isBuyF = parsed.decision === 'BUY';
      const inst = (parsed.instrument || '').toUpperCase();
      let distSLMin;
      if (inst.includes('XAU')) distSLMin = 1.5;
      else if (inst.includes('JPY')) distSLMin = 0.10;
      else if (inst.includes('BTC')) distSLMin = 100;
      else if (inst.includes('ETH')) distSLMin = 8;
      else if (inst.match(/EUR|GBP|AUD|NZD|CHF|CAD/) && !inst.includes('JPY')) distSLMin = 0.0010;
      else if (inst.match(/NAS|US30|SPX|US100|US500|GER40|DAX/)) distSLMin = 15;
      else distSLMin = 0;
      if (distSLMin > 0 && distSL < distSLMin) {
        console.log('[VALIDATION-SL] Distance SL ' + distSL + ' < min ' + distSLMin + ' pour ' + inst);
        parsed.decision = 'NE PAS TRADER';
        parsed.slDistAlerte = 'SL trop serré (' + distSL.toFixed(5) + ' < ' + distSLMin + ' pour ' + inst + ')';
      }
      if (parsed.decision !== 'NE PAS TRADER') {
        const tps = ['tp1', 'tp2', 'tp3'].map(k => parsed[k] ? parseFloat(parsed[k]) : null);
        for (let i = 0; i < tps.length; i++) {
          if (tps[i] === null || isNaN(tps[i])) continue;
          if (Math.abs(tps[i] - ent) < distSL * 0.8) {
            parsed.decision = 'NE PAS TRADER';
            parsed.tpDistAlerte = 'TP' + (i+1) + ' trop proche entrée (RR < 0.8)';
            break;
          }
          if (isBuyF && tps[i] <= ent) { parsed.decision = 'NE PAS TRADER'; parsed.tpDistAlerte = 'TP' + (i+1) + ' sous entrée pour BUY'; break; }
          if (!isBuyF && tps[i] >= ent) { parsed.decision = 'NE PAS TRADER'; parsed.tpDistAlerte = 'TP' + (i+1) + ' au-dessus entrée pour SELL'; break; }
        }
        // Vérifier ordre TPs
        const tpsValides = tps.filter(t => t !== null && !isNaN(t));
        if (tpsValides.length >= 2 && parsed.decision !== 'NE PAS TRADER') {
          for (let i = 1; i < tpsValides.length; i++) {
            const ordre = isBuyF ? tpsValides[i] > tpsValides[i-1] : tpsValides[i] < tpsValides[i-1];
            if (!ordre) { parsed.decision = 'NE PAS TRADER'; parsed.tpOrdreAlerte = 'TPs mauvais ordre'; break; }
          }
        }
      }
    }

    const analysisId = uuidv4();

    await analysesDb.insertAsync({
      _id: analysisId,
      userId: req.session.userId,
      accountId: req.session.userMT5AccountId || null, // FIX multi-comptes : qui a tradé
      decision: parsed.decision,
      entry: parsed.entree,
      entree: parsed.entree,
      sl: parsed.sl,
      tp: parsed.tp1, tp1: parsed.tp1, tp2: parsed.tp2, tp3: parsed.tp3,
      tp1Source: parsed.tp1Source || null,
      tp2Source: parsed.tp2Source || null,
      tp3Source: parsed.tp3Source || null,
      tp1RR: parsed.tp1RR || null,
      tp2RR: parsed.tp2RR || null,
      tp3RR: parsed.tp3RR || null,
      conceptUtilise: parsed.conceptUtilise || null,
      conceptsTestes: parsed.conceptsTestes || null,
      score: parsed.score,
      instrument: parsed.instrument,
      lots: parsed.lots,
      slPips: parsed.slPips,
      risquePct: parsed.risquePct,
      montantRisque: parsed.montantRisque,
      manipulation: parsed.manipulation,
      crt: parsed.crt,
      crtKasper: parsed.crtKasper || null,
      ob: parsed.ob || null,
      fvg: parsed.fvg || null,
      entreeLevel: parsed.entreeLevel || null,
      confluences: parsed.confluences || null,
      rangeHaut: parsed.rangeHaut,
      rangeBas: parsed.rangeBas,
      feedbackResult: null,
      createdAt: new Date()
    });

    if (user.role !== 'admin') await db.updateAsync({ _id: user._id }, { $inc: { analysisCount: 1 } }, {});
    const analysesLeft = analysesRestantes(user);

    // ─── ALERTE SETUP A+ (score >= 8) : email broadcast + notif in-app ──
    if ((parsed.score || 0) >= 8 && (parsed.decision === 'BUY' || parsed.decision === 'SELL')) {
      // 1. Email à tous les clients abonnés (arrière-plan)
      envoyerAlerteSetupAPlus(parsed, analysisId).catch(e =>
        console.log('[ALERTE-EMAIL] Erreur silencieuse:', e.message)
      );
      // 2. Notification in-app pour TOUS les clients (bandeau Setup A+ dans l'app)
      //    On l'enregistre pour CHAQUE client abonné → ils le voient via polling 60s
      (async () => {
        try {
          const sc = parseFloat(parsed.score) || 0;
          const urgence = sc >= 9.5 ? '🔴 ULTRA URGENT' : sc >= 9 ? '🟠 URGENT' : '🟡 SETUP A+';

          // Données communes du setup (sans lots — recalculé par client)
          const entreeNum = parseFloat(parsed.entree) || 0;
          const slNum     = parseFloat(parsed.sl)     || 0;
          const slDistanceDollars = entreeNum && slNum ? Math.abs(entreeNum - slNum) : null;
          const instrument = parsed.instrument || 'XAUUSD';
          const risquePct  = sc >= 8 ? 3 : sc >= 6 ? 2 : 1;

          // GATING : notifs in-app uniquement aux Pro/Elite (cohérence avec email)
          const clients = await db.findAsync({
            role: { $ne: 'admin' },
            subscribed: true,
            isVerified: true,
            banned: { $ne: true },
            plan: { $in: ['premium', 'elite', 'pro'] }
          });

          for (const client of clients) {
            // ─── LOT PERSONNALISÉ AU CAPITAL DU CLIENT ──────────────────────
            // Chaque client a son propre capital → lot différent pour chacun
            // Utilise le même algorithme que l'analyse normale (calculerLots)
            let lotsClient = null;
            let montantRisqueClient = null;
            const capitalClient = client.mt5 && client.mt5.capital ? parseFloat(client.mt5.capital) : null;
            if (capitalClient && capitalClient > 0 && slDistanceDollars) {
              const lotsCalc = calculerLots(capitalClient, risquePct, parsed.slPips || slDistanceDollars, instrument, slDistanceDollars);
              if (lotsCalc) {
                // Appliquer le facteur de risque du client (drawdown jour)
                const { facteur } = await getFacteurRisque(client._id, capitalClient).catch(() => ({ facteur: 1 }));
                lotsClient = Math.max(0.01, Math.round(lotsCalc * facteur * 100) / 100);
                montantRisqueClient = (capitalClient * risquePct / 100 * facteur).toFixed(2);
              }
            }

            await creerNotification(
              client._id,
              'setup_aplus',
              urgence + ' — ' + parsed.decision + ' ' + instrument + ' | Score ' + sc + '/10',
              'Entrée ' + (parsed.entree || '—') + ' · SL ' + (parsed.sl || '—') + ' · TP1 ' + (parsed.tp1 || '—'),
              {
                decision: parsed.decision,
                instrument,
                entree: parsed.entree,
                sl: parsed.sl,
                tp1: parsed.tp1,
                tp2: parsed.tp2,
                tp3: parsed.tp3,
                score: sc,
                // Lot et montant PERSONNALISÉS au capital du client
                lots: lotsClient,
                montantRisque: montantRisqueClient,
                capitalClient,
                risquePct,
                // ID de l'analyse source → permet d'afficher le statut TP/SL plus tard
                sourceAnalysisId: analysisId
              }
            );
          }
        } catch(e) { console.log('[NOTIF-APLUS] Erreur:', e.message); }
      })();
    }

    // Attacher Fibonacci à parsed pour que le frontend l'affiche
    try {
      if (global._ictCache && global._ictCache[req.session.userId]) {
        const ictData = global._ictCache[req.session.userId].analyse;
        if (ictData) {
          if (ictData.fibonacci) parsed.fibonacci = ictData.fibonacci;
          if (ictData.fibonacciH1) parsed.fibonacciH1 = ictData.fibonacciH1;
        }
      }
    } catch(e) {}

    // ═══ MODE DEBUG : tracer TOUS les filtres déclenchés ═══════
    // Permet d'identifier précisément quel filtre annule un trade.
    // Le frontend affiche ces infos pour debug.
    parsed.debugFilters = {
      scoreInitial: parsed.scoreInitial !== undefined ? parsed.scoreInitial : parsed.score,
      scoreFinal: parsed.score,
      decisionInitiale: parsed.decisionInitiale || parsed.decision,
      decisionFinale: parsed.decision,
      filtresDeclenches: []
    };
    // Lister les alertes détectables sur parsed (qui ont annulé ou modifié le trade)
    const alertesPossibles = [
      { champ: 'piegeRangeAlerte', icon: '🚫', label: 'Piège range Asian' },
      { champ: 'momentumAlerte', icon: '⚡', label: 'Momentum contraire' },
      { champ: 'reajustAlerte', icon: '🎯', label: 'Réajustement entrée' },
      { champ: 'protectionsAlertes', icon: '🛡️', label: 'Protections avancées' },
      { champ: 'hardBlockAlerte', icon: '🚫', label: 'Hard-block ICT' },
      { champ: 'slDirectionAlerte', icon: '⚠️', label: 'SL direction corrigée' },
      { champ: 'scoreGuardAlerte', icon: '📉', label: 'Score < 6' },
      { champ: 'entreeInvalideAlerte', icon: '🔢', label: 'Entrée non numérique' },
      { champ: 'numInvalideAlerte', icon: '🔢', label: 'SL/TP non numérique' }
    ];
    alertesPossibles.forEach(a => {
      if (parsed[a.champ]) {
        parsed.debugFilters.filtresDeclenches.push({
          icon: a.icon,
          label: a.label,
          message: parsed[a.champ]
        });
      }
    });
    // Logger côté serveur pour les logs Render
    if (parsed.debugFilters.filtresDeclenches.length > 0) {
      console.log('[DEBUG-FILTERS] Score: ' + parsed.score + ' | Décision: ' + parsed.decision + ' | Filtres: ' +
        parsed.debugFilters.filtresDeclenches.map(f => f.icon + ' ' + f.label).join(' | '));
    }

    res.json({ ...parsed, analysesLeft, analysisId });

  } catch (err) {
    allFiles.forEach(f => { try { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); } catch(e){} });
    res.status(500).json({ error: 'Erreur: ' + err.message });
  } finally {
    // ✅ FIX BUG 11 : libérer le slot d'analyse en cours
    clearTimeout(cleanupTimer);
    if (global._analysesEnCours) global._analysesEnCours.delete(req.session.userId);
  }
});


// ─── GET /api/trade/:id — charger un trade depuis un lien email ──────
app.get('/api/trade/:id', checkAuth, async (req, res) => {
  try {
    const analyse = await analysesDb.findOneAsync({ _id: req.params.id });
    if (!analyse) return res.status(404).json({ error: 'Trade non trouvé' });
    const viewer = await db.findOneAsync({ _id: req.session.userId });
    let lotsViewer = null, montantViewer = null;
    if (viewer && viewer.mt5 && viewer.mt5.capital) {
      const cap = parseFloat(viewer.mt5.capital) || 0;
      const entreeN = parseFloat(analyse.entry) || 0;
      const slN = parseFloat(analyse.sl) || 0;
      const slDist = entreeN && slN ? Math.abs(entreeN - slN) : 0;
      if (cap > 0 && slDist > 0) {
        const sc = parseFloat(analyse.score) || 0;
        const riskPct = sc >= 8 ? 3 : sc >= 6 ? 2 : 1;
        const calc = calculerLots(cap, riskPct, slDist, analyse.instrument || 'XAUUSD', slDist);
        if (calc) {
          const { facteur } = await getFacteurRisque(viewer._id, cap).catch(() => ({ facteur: 1 }));
          lotsViewer = Math.max(0.01, Math.round(calc * facteur * 100) / 100);
          montantViewer = (cap * riskPct / 100 * facteur).toFixed(2);
        }
      }
    }
    res.json({
      analysisId: analyse._id,
      decision: analyse.decision,
      instrument: analyse.instrument || 'XAUUSD',
      entree: analyse.entry,
      sl: analyse.sl,
      tp1: analyse.tp || analyse.tp1,
      tp2: analyse.tp2,
      tp3: analyse.tp3,
      score: analyse.score,
      lots: lotsViewer,
      montantRisque: montantViewer,
      feedbackResult: analyse.feedbackResult,
      createdAt: analyse.createdAt
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// FIX : endpoint pour les paiements en attente (notif admin)
app.get('/admin/pending-payments', checkAdmin, async (req, res) => {
  try {
    const users = await db.findAsync({ paymentStatus: 'pending_payment' });
    const prix = chargerPrix();
    const sorted = users.sort((a, b) => new Date(b.packDemandeAt || 0) - new Date(a.packDemandeAt || 0));
    res.json({
      count: sorted.length,
      pending: sorted.map(u => ({
        _id: u._id,
        email: u.email,
        packDemande: u.packDemande,
        packPrix: prix[u.packDemande] || null,
        packDemandeAt: u.packDemandeAt,
        createdAt: u.createdAt
      }))
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// FIX : endpoint pour le user de voir son statut pack
app.get('/api/me/pack-status', async (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  try {
    const user = await db.findOneAsync({ _id: req.session.userId });
    if (!user) return res.json({ status: 'unknown' });
    const prix = chargerPrix();
    res.json({
      status: user.paymentStatus,
      pack: user.packDemande,
      packLabel: user.packDemande ? (prix[user.packDemande]?.label || user.packDemande) : null,
      packPrix: user.packDemande ? prix[user.packDemande] : null,
      subscribed: user.subscribed,
      plan: user.plan,
      analysesLeft: user.analysisMax - (user.analysisCount || 0)
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
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

// ═══ CONFIG PRIX DES PACKS (modifiable via admin) ═══
const PRIX_FILE = path.join(DATA_DIR, 'prix-packs.json');
const PRIX_DEFAUT = {
  starter: { prix: 25, devise: 'EUR', periode: 'semaine', analyses: 30, label: 'Starter' },
  pro: { prix: 100, devise: 'EUR', periode: 'semaine', analyses: 150, label: 'Pro' },
  elite: { prix: 75, devise: 'EUR', periode: 'semaine', analyses: 999999, label: 'Elite' }
};
function chargerPrix() {
  try {
    if (fs.existsSync(PRIX_FILE)) {
      const data = JSON.parse(fs.readFileSync(PRIX_FILE, 'utf-8'));
      return { ...PRIX_DEFAUT, ...data };
    }
  } catch(e) {}
  return PRIX_DEFAUT;
}
function sauverPrix(prix) {
  try { fs.writeFileSync(PRIX_FILE, JSON.stringify(prix, null, 2)); return true; }
  catch(e) { return false; }
}
// ═══ DB DES ERREURS SERVEUR (capturées automatiquement) ═══
// FIX : utiliser @seald-io/nedb comme toutes les autres DBs (évite crash si nedb-promises absent)
const errorsDb = new Datastore({ filename: path.join(DATA_DIR, 'errors.db'), autoload: true });

// Capture des erreurs Node non-catchées + console.error
const _origConsoleError = console.error.bind(console);
console.error = function(...args) {
  _origConsoleError(...args);
  try {
    const msg = args.map(a => {
      if (a instanceof Error) return a.stack || a.message;
      if (typeof a === 'object') { try { return JSON.stringify(a); } catch(e) { return String(a); } }
      return String(a);
    }).join(' ');
    errorsDb.insertAsync({
      _id: uuidv4(),
      type: 'console_error',
      message: msg.slice(0, 8000),
      timestamp: new Date(),
      resolved: false
    }).catch(() => {});
  } catch(e) {}
};

process.on('uncaughtException', (err) => {
  _origConsoleError('[UNCAUGHT]', err);
  errorsDb.insertAsync({
    _id: uuidv4(),
    type: 'uncaught_exception',
    message: (err.stack || err.message || String(err)).slice(0, 8000),
    timestamp: new Date(),
    resolved: false
  }).catch(() => {});
});

process.on('unhandledRejection', (reason) => {
  _origConsoleError('[UNHANDLED-REJECTION]', reason);
  errorsDb.insertAsync({
    _id: uuidv4(),
    type: 'unhandled_rejection',
    message: (reason && reason.stack ? reason.stack : String(reason)).slice(0, 8000),
    timestamp: new Date(),
    resolved: false
  }).catch(() => {});
});

// Route : récupérer la liste des erreurs récentes (paginé)
app.get('/admin/errors', checkAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const onlyUnresolved = req.query.unresolved === '1';
    const query = onlyUnresolved ? { resolved: false } : {};
    const errors = await errorsDb.find(query).sort({ timestamp: -1 }).limit(limit);
    res.json({ errors, total: errors.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Route : marquer une erreur comme résolue
app.post('/admin/errors/:id/resolve', checkAdmin, async (req, res) => {
  try {
    await errorsDb.updateAsync({ _id: req.params.id }, { $set: { resolved: true, resolvedAt: new Date() } });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Route : supprimer une erreur
app.delete('/admin/errors/:id', checkAdmin, async (req, res) => {
  try {
    await errorsDb.removeAsync({ _id: req.params.id }, {});
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Route : effacer toutes les erreurs résolues
app.post('/admin/errors/clear-resolved', checkAdmin, async (req, res) => {
  try {
    const result = await errorsDb.removeAsync({ resolved: true }, { multi: true });
    res.json({ success: true, deleted: result });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Route : reporter une erreur depuis le frontend
app.post('/api/error-report', async (req, res) => {
  try {
    const { message, stack, url, line, col } = req.body;
    if (!message) return res.status(400).json({ error: 'message requis' });
    await errorsDb.insertAsync({
      _id: uuidv4(),
      type: 'frontend_error',
      message: String(message).slice(0, 2000),
      stack: String(stack || '').slice(0, 4000),
      url: String(url || '').slice(0, 500),
      line: line || null,
      col: col || null,
      userId: req.session?.userId || null,
      timestamp: new Date(),
      resolved: false
    });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Servir les pages dédiées Admindoctor.html et Adminlogs.html (noms uploadés)
app.get('/Admindoctor.html', checkAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'Admindoctor.html'));
});
app.get('/Adminlogs.html', checkAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'Adminlogs.html'));
});
// Alias pour compatibilité
app.get('/admin/doctor.html', checkAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'Admindoctor.html'));
});
app.get('/admin/logs.html', checkAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'Adminlogs.html'));
});

// ═══ AI DOCTOR — Chat IA d'aide au debug ═══
// Le user colle un log/erreur dans le chat admin, l'IA répond avec le code corrigé
app.post('/admin/ai-doctor', checkAdmin, async (req, res) => {
  try {
    const { message, history } = req.body;
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'Message requis' });
    }
    if (message.length > 8000) {
      return res.status(400).json({ error: 'Message trop long (max 8000 caractères)' });
    }

    // Construire l'historique des messages pour Claude
    const messages = [];
    if (Array.isArray(history)) {
      // Garder max 10 derniers échanges pour économiser tokens
      const recentHistory = history.slice(-20);
      for (const h of recentHistory) {
        if (h.role && h.content && (h.role === 'user' || h.role === 'assistant')) {
          messages.push({ role: h.role, content: String(h.content).slice(0, 4000) });
        }
      }
    }
    messages.push({ role: 'user', content: message });

    const systemPrompt = `Tu es l'AI Doctor de la plateforme J4keIA / AI-Mazza — un assistant expert en debug pour Leon (le développeur).

Contexte technique du projet :
- Backend : Node.js + Express + NeDB (DBs locales) + MetaApi (trading MT5) + Anthropic Claude API
- Frontend : HTML/CSS/JS vanilla, design néon cyan/gold "Orbitron"
- Déployé sur Render (filesystem éphémère sauf /db si configuré)
- Stack : sessions express-session, multer pour uploads images, sharp pour PNG, nodemailer pour OTP

Ton rôle :
- Tu reçois des logs d'erreurs, des extraits de code buggés, ou des descriptions de bugs
- Tu analyses le problème
- Tu fournis LE CODE CORRIGÉ prêt à copier-coller
- Tu expliques BRIÈVEMENT le bug et la solution

Format de réponse :
1. 🔍 **Diagnostic** : 1-2 phrases sur la cause
2. 🛠️ **Solution** : le code corrigé dans un bloc \`\`\`javascript ou \`\`\`html
3. ⚠️ **Risques** (si pertinent) : ce qu'il faut vérifier après la modif

Sois CONCIS et DIRECT. Pas de blabla inutile. Code en premier, explication courte ensuite.
Si le bug n'est pas clair, demande UNE info précise avant de proposer.`;

    const Anthropic = require('@anthropic-ai/sdk').default || require('@anthropic-ai/sdk').Anthropic || require('@anthropic-ai/sdk');
    const anthropicClient = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const response = await anthropicClient.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 3000,
      system: systemPrompt,
      messages: messages
    });

    const reply = response.content && response.content[0] ? response.content[0].text : 'Pas de réponse';
    res.json({ success: true, reply });
  } catch(e) {
    console.error('[AI-DOCTOR] Erreur:', e.message);
    res.status(500).json({ error: 'Erreur IA: ' + e.message });
  }
});

// ═══ STATS IA PERSO (compteur leçons + setups gagnants) ═══
app.get('/api/ia-stats', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  try {
    const [lecons, setups, analyses] = await Promise.all([
      leconsDb.findAsync({ userId: req.session.userId }),
      setupsGagnantsDb.findAsync({ userId: req.session.userId }),
      analysesDb.findAsync({ userId: req.session.userId, decision: { $in: ['BUY', 'SELL'] } })
    ]);
    // Calcul du niveau de maturité (gamification)
    const total = lecons.length + setups.length;
    let niveau, badge;
    if (total >= 50) { niveau = 'EXPERT'; badge = '🏆'; }
    else if (total >= 20) { niveau = 'AVANCE'; badge = '⭐'; }
    else if (total >= 5) { niveau = 'EN APPRENTISSAGE'; badge = '🌱'; }
    else { niveau = 'DEBUTANT'; badge = '🆕'; }
    res.json({
      lecons: lecons.length,
      setupsGagnants: setups.length,
      analysesTotal: analyses.length,
      niveau, badge
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══ STATS TP/SL PAR CLIENT (dashboard admin) ═══
app.get('/admin/clients-trades-stats', checkAdmin, async (req, res) => {
  try {
    const users = await db.findAsync({ role: { $ne: 'admin' } });
    const il_y_a_30j = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const stats = [];
    for (const user of users) {
      const analyses = await analysesDb.findAsync({
        userId: user._id,
        decision: { $in: ['BUY', 'SELL'] },
        createdAt: { $gte: il_y_a_30j }
      });
      const tradesAvecResult = analyses.filter(a =>
        a.feedbackResult === 'tp' || a.feedbackResult === 'sl' ||
        (typeof a.tradeProfit === 'number')
      );
      const tps = tradesAvecResult.filter(a =>
        a.feedbackResult === 'tp' || (typeof a.tradeProfit === 'number' && a.tradeProfit > 0)
      );
      const sls = tradesAvecResult.filter(a =>
        a.feedbackResult === 'sl' || (typeof a.tradeProfit === 'number' && a.tradeProfit < 0)
      );

      // Calcul profit total
      let profitTotal = 0;
      for (const t of tradesAvecResult) {
        if (typeof t.tradeProfit === 'number') profitTotal += t.tradeProfit;
      }

      // Dernier trade
      let dernierTrade = null;
      if (tradesAvecResult.length) {
        const sorted = [...tradesAvecResult].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        const last = sorted[0];
        const result = last.feedbackResult === 'tp' || (typeof last.tradeProfit === 'number' && last.tradeProfit > 0) ? 'TP' : 'SL';
        dernierTrade = {
          result,
          instrument: last.instrument || 'XAUUSD',
          direction: last.decision,
          profit: typeof last.tradeProfit === 'number' ? last.tradeProfit : null,
          date: last.createdAt
        };
      }

      if (analyses.length > 0) {
        stats.push({
          userId: user._id,
          email: user.email,
          plan: user.plan || 'free',
          tps: tps.length,
          sls: sls.length,
          tradesTotal: tradesAvecResult.length,
          analysesTotal: analyses.length,
          winRate: tradesAvecResult.length > 0 ? Math.round((tps.length / tradesAvecResult.length) * 100) : 0,
          profitTotal: +profitTotal.toFixed(2),
          dernierTrade
        });
      }
    }

    // Tri par profit total décroissant
    stats.sort((a, b) => b.profitTotal - a.profitTotal);
    res.json({ clients: stats, total: stats.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/prix-packs', checkAdmin, (req, res) => { res.json(chargerPrix()); });
app.get('/api/prix-packs', (req, res) => { res.json(chargerPrix()); });
app.post('/admin/prix-packs', checkAdmin, (req, res) => {
  try {
    const { starter, pro, elite } = req.body;
    if (!starter || !pro || !elite) return res.status(400).json({ error: 'Tous les packs requis' });
    for (const [k, v] of Object.entries({ starter, pro, elite })) {
      if (typeof v.prix !== 'number' || v.prix < 0 || v.prix > 99999) {
        return res.status(400).json({ error: 'Prix invalide pour ' + k });
      }
    }
    const nv = {
      starter: { ...PRIX_DEFAUT.starter, ...starter },
      pro: { ...PRIX_DEFAUT.pro, ...pro },
      elite: { ...PRIX_DEFAUT.elite, ...elite }
    };
    if (sauverPrix(nv)) res.json({ success: true, prix: nv });
    else res.status(500).json({ error: 'Sauvegarde échouée' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/alerte-email', checkAdmin, async (req, res) => {
  try {
    const { decision, instrument, entree, sl, tp1, tp2, tp3, score, raison, lots } = req.body;
    if (!decision || !instrument || !score) return res.status(400).json({ error: 'decision, instrument, score requis' });
    const fakeParsed = { decision, instrument, entree, sl, tp1, tp2, tp3, score: parseFloat(score), lots,
      raisonCourte: raison || 'Test manuel admin' };
    await envoyerAlerteSetupAPlus(fakeParsed, 'ADMIN-' + Date.now());
    res.json({ success: true, message: 'Alerte envoyée à tous les clients abonnés' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// FIX : permettre à l'admin de valider DIRECTEMENT le pack demandé
app.post('/admin/validate-pending/:id', checkAdmin, async (req, res) => {
  try {
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Utilisateur introuvable' });
    if (!user.packDemande) return res.json({ error: 'Pas de pack en attente' });

    // Calculer maxAnalyses selon le pack
    let analysisMax = 30;
    if (user.packDemande === 'pro' || user.packDemande === 'premium') analysisMax = 150;
    else if (user.packDemande === 'elite') analysisMax = 999999;

    // 7 jours d'accès (modifie si tu veux 30 jours)
    const paidUntil = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await db.updateAsync({ _id: req.params.id }, { $set: {
      subscribed: true,
      paymentStatus: 'paid',
      plan: user.packDemande,
      analysisMax: analysisMax,
      analysisCount: 0,
      paidUntil: paidUntil,
      validatedAt: new Date(),
      packDemande: null // efface la demande
    } });

    console.log('[ADMIN-VALIDATE] ' + user.email + ' → pack ' + user.packDemande + ' validé');

    // Notification au user
    if (typeof creerNotification === 'function') {
      try {
        await creerNotification(req.params.id, 'pack_active',
          '🎉 Ton pack ' + user.packDemande.toUpperCase() + ' est actif !',
          'Tu peux maintenant profiter de toutes les fonctionnalités. Bon trading !',
          { plan: user.packDemande });
      } catch(e) {}
    }

    res.json({ success: true, plan: user.packDemande, analysisMax });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// FIX : permettre à l'admin de refuser/annuler un pack demandé
app.post('/admin/reject-pending/:id', checkAdmin, async (req, res) => {
  try {
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Utilisateur introuvable' });
    await db.updateAsync({ _id: req.params.id }, { $set: {
      paymentStatus: 'pending',
      packDemande: null,
      packRefusedAt: new Date()
    } });
    if (typeof creerNotification === 'function') {
      try {
        await creerNotification(req.params.id, 'pack_refused',
          '❌ Demande de pack non validée',
          'Ta demande de pack n\'a pas été validée. Contacte l\'admin si problème.',
          {});
      } catch(e) {}
    }
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/payment/:id', checkAdmin, async (req, res) => {
  try {
    const { status, plan, note } = req.body;
    const user = await db.findOneAsync({ _id: req.params.id });
    if (!user) return res.json({ error: 'Introuvable' });
    const subscribed = status === 'paid';
    let analysisMax = 2;
    let normalizedPlan = plan;
    if (subscribed) {
      // FIX BUG : "pro" était traité comme "starter" (fallback). Maintenant "pro" = 150 analyses.
      if (plan === 'starter') analysisMax = 30;
      else if (plan === 'pro' || plan === 'premium') {
        analysisMax = 150;
        normalizedPlan = 'pro';
      }
      else if (plan === 'elite') analysisMax = 999999; // illimité
      else analysisMax = 30;
    }
    let paidUntil = null;
    if (subscribed) {
      // 7 jours complets garantis → dimanche soir après J+7
      const now = new Date();
      const plusSeptJours = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      const dayApres7 = plusSeptJours.getUTCDay();
      const daysUntilSunday = dayApres7 === 0 ? 0 : 7 - dayApres7;
      const nextSunday = new Date(plusSeptJours);
      nextSunday.setUTCDate(plusSeptJours.getUTCDate() + daysUntilSunday);
      nextSunday.setUTCHours(23, 59, 59, 999);
      paidUntil = nextSunday.toISOString();
      console.log('[PAYMENT] paidUntil:', paidUntil);
    }
    await db.updateAsync({ _id: req.params.id }, {
      $set: { paymentStatus: status, plan: subscribed ? normalizedPlan : 'free', paymentNote: note || '', subscribed, analysisMax, analysisCount: 0, paidUntil }
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
// ═══ HELPERS MULTI-COMPTES MT5 ═══
// L'ancien format avait user.mt5 = { ... } (1 seul compte)
// Le nouveau format a user.mt5Accounts = [ { id, label, ... } ] + user.activeMT5AccountId
// Cette fonction normalise et retourne le compte actif

function getMT5AccountLimit(user) {
  const plan = (user.plan || 'free').toLowerCase();
  if (plan === 'admin' || user.role === 'admin') return 999;
  if (plan === 'elite') return 5;
  if (plan === 'pro' || plan === 'premium') return 1;
  return 0;
}

async function getActiveMT5(userId) {
  const user = await db.findOneAsync({ _id: userId });
  if (!user) return null;
  // Nouveau format : tableau de comptes
  if (Array.isArray(user.mt5Accounts) && user.mt5Accounts.length > 0) {
    const activeId = user.activeMT5AccountId || user.mt5Accounts[0].id;
    return user.mt5Accounts.find(a => a.id === activeId) || user.mt5Accounts[0];
  }
  // Ancien format : objet unique → on le retourne tel quel (rétrocompat)
  if (user.mt5) {
    return { ...user.mt5, id: 'legacy', label: user.mt5.login + ' (legacy)' };
  }
  return null;
}

async function getAllMT5Accounts(userId) {
  const user = await db.findOneAsync({ _id: userId });
  if (!user) return [];
  if (Array.isArray(user.mt5Accounts) && user.mt5Accounts.length > 0) {
    return user.mt5Accounts;
  }
  if (user.mt5) {
    return [{ ...user.mt5, id: 'legacy', label: user.mt5.login + ' (legacy)' }];
  }
  return [];
}

// Migration auto : si user a user.mt5 mais pas user.mt5Accounts, on convertit
async function migrateMT5Format(userId) {
  const user = await db.findOneAsync({ _id: userId });
  if (!user || !user.mt5) return;
  if (Array.isArray(user.mt5Accounts) && user.mt5Accounts.length > 0) return;
  const accountId = uuidv4();
  const account = {
    id: accountId,
    label: user.mt5.login + ' (' + (user.mt5.server || 'MT5') + ')',
    ...user.mt5,
    addedAt: user.mt5.connectedAt || new Date().toISOString()
  };
  await db.updateAsync(
    { _id: userId },
    { $set: { mt5Accounts: [account], activeMT5AccountId: accountId } }
  );
  console.log('[MIGRATION-MT5] User ' + userId + ' converti vers multi-comptes');
}

async function saveMT5Credentials(userId, mt5Data) {
  const encryptedPassword = encryptStr(mt5Data.password);
  const user = await db.findOneAsync({ _id: userId });
  const limit = getMT5AccountLimit(user);

  // Vérifier que l'utilisateur a le droit (Pro=1, Elite=5, Admin=999)
  if (limit === 0) {
    throw new Error('Ton plan ne donne pas accès à MT5');
  }

  // Migration auto si format ancien
  await migrateMT5Format(userId);

  // Récupérer les comptes existants (post-migration)
  const userFresh = await db.findOneAsync({ _id: userId });
  let accounts = Array.isArray(userFresh.mt5Accounts) ? [...userFresh.mt5Accounts] : [];

  // Cherche un compte existant avec le même login + serveur
  const existingIdx = accounts.findIndex(a =>
    String(a.login) === String(mt5Data.login) && a.server === mt5Data.server
  );

  const accountData = {
    id: existingIdx >= 0 ? accounts[existingIdx].id : uuidv4(),
    label: mt5Data.login + ' (' + (mt5Data.server || 'MT5') + ')',
    login: String(mt5Data.login),
    passwordEnc: encryptedPassword,
    server: mt5Data.server,
    accountType: mt5Data.accountType || 'demo',
    metaApiAccountId: mt5Data.metaApiAccountId,
    capital: mt5Data.capital || null,
    balance: mt5Data.balance != null ? mt5Data.balance : mt5Data.capital || null,
    credit: mt5Data.credit || 0,
    equity: mt5Data.equity || mt5Data.capital || null,
    currency: mt5Data.currency || 'USD',
    connectedAt: new Date().toISOString(),
    addedAt: existingIdx >= 0 ? accounts[existingIdx].addedAt : new Date().toISOString()
  };

  if (existingIdx >= 0) {
    accounts[existingIdx] = accountData;
  } else {
    if (accounts.length >= limit) {
      throw new Error('Limite atteinte : ton plan permet ' + limit + ' compte(s) MT5 max. Supprime-en un pour en ajouter un nouveau.');
    }
    accounts.push(accountData);
  }

  await db.updateAsync(
    { _id: userId },
    { $set: {
      mt5Accounts: accounts,
      activeMT5AccountId: accountData.id,
      mt5: accountData
    } }
  );
}

// ─── POST /mt5/connect : connecter le compte MT5 du client ──────────
// Réutilise les comptes MetaApi existants (créés par le bot ou par le site)
// Permet aussi de changer de compte (écrase l'ancienne connexion proprement)
app.post('/mt5/connect', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  if (!metaApi) return res.status(500).json({ error: 'MetaApi non configuré côté serveur' });
  // Vérification plan Premium/Elite
  const _u = await db.findOneAsync({ _id: req.session.userId });
  if (!hasPremiumAccess(_u)) return res.status(403).json({ error: 'mt5_plan_required', message: '🔒 Connexion MT5 réservée aux plans Pro et Elite. Contacte @bigtazz pour upgrader.' });

  // ─── RESTRICTION PLAN : MT5 réservé aux plans Premium et Elite ──
  // Les plans Free et Starter n'ont pas accès à la connexion MT5
  const userForPlan = await db.findOneAsync({ _id: req.session.userId });
  const planUser = (userForPlan && userForPlan.plan) ? userForPlan.plan.toLowerCase() : 'free';
  // FIX BUG : 'pro' était oublié alors que c'est le nom stocké en DB (voir /admin/payment)
  const plansAutorisesMT5 = ['pro', 'premium', 'elite', 'admin'];
  if (userForPlan && userForPlan.role !== 'admin' && !plansAutorisesMT5.includes(planUser)) {
    return res.status(403).json({
      error: 'mt5_plan_required',
      message: 'La connexion MT5 est réservée aux plans Premium et Elite. Contacte @bigtazz pour upgrader.'
    });
  }

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
      console.log('[MT5-CONNECT] ✅ Capital récupéré: balance=' + accountInfo.balance + ' credit=' + (accountInfo.credit || 0) + ' equity=' + (accountInfo.equity || accountInfo.balance) + ' ' + accountInfo.currency);
    } catch(syncErr) {
      console.log('[MT5-CONNECT] Sync failed:', syncErr.message);
      // ON NE TOUCHE PAS AU UNDEPLOY — laisse le watchdog faire son job
      throw new Error('La connexion au broker a démarré mais la sync échoue. Réessaye dans 1 minute.');
    }

    // ─── CAPITAL EFFECTIF = balance + credit (bonus broker utilisable) ───
    // Si le user a 0€ balance mais 500€ credit, on utilise 500 pour calculer les lots
    // sinon le bloc lots ne s'affichera pas et le user bloquera
    const capitalEffectif = (parseFloat(accountInfo.balance) || 0) + (parseFloat(accountInfo.credit) || 0);
    if (capitalEffectif <= 0) {
      console.log('[MT5-CONNECT] ⚠️ Capital effectif = 0 (balance + credit). Le compte ne pourra pas trader.');
    }

    // ─── Étape 5 : Sauvegarder les credentials chiffres ────────────
    await saveMT5Credentials(req.session.userId, {
      login,
      password,
      server,
      accountType: accountType || 'demo',
      metaApiAccountId: account.id,
      capital: capitalEffectif,           // balance + credit
      balance: accountInfo.balance,        // garde aussi le détail
      credit: accountInfo.credit || 0,
      equity: accountInfo.equity || accountInfo.balance,
      currency: accountInfo.currency
    });

    // ─── Étape 6 : NE PAS UNDEPLOY ────────────────────────────────
    // On laisse le compte deployed pour quelques minutes :
    // - L'utilisateur peut placer un ordre juste apres
    // - Le watchdog l'undeploy automatiquement apres 5 min d'inactivite
    // - Evite les race conditions deploy/undeploy trop rapides
    console.log('[MT5-CONNECT] ✅ Connexion reussie — compte reste deployed (watchdog auto-undeploy dans 5 min)');

    res.json({
      success: true,
      capital: capitalEffectif,
      balance: accountInfo.balance,
      credit: accountInfo.credit || 0,
      currency: accountInfo.currency,
      login: accountInfo.login,
      server: accountInfo.server,
      name: accountInfo.name,
      reused: !!account
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
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  const _u = await db.findOneAsync({ _id: req.session.userId });
  if (!hasPremiumAccess(_u)) return res.status(403).json({ error: 'mt5_plan_required', message: '🔒 Réservé aux plans Pro et Elite.' });
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
    // ─── FIX : Undeploy le compte MetaApi AVANT de supprimer ────────
    // Sans ça, MetaApi continue à facturer même après déconnexion
    const user = await db.findOneAsync({ _id: req.session.userId });
    if (user && user.mt5 && user.mt5.metaApiAccountId && metaApi) {
      try {
        const account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
        if (account && account.state !== 'UNDEPLOYED') {
          await account.undeploy();
          trackUndeploy(account.id);
          console.log('[MT5-DISCONNECT] Compte undeploye: ' + user.mt5.metaApiAccountId);
        }
      } catch(undeployErr) {
        // Ne pas bloquer la déconnexion si l'undeploy échoue
        console.log('[MT5-DISCONNECT] Undeploy échoué (watchdog prendra le relais):', undeployErr.message);
      }
    }
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
// Détection broker depuis le nom du serveur MT5
function detectBroker(serverName) {
  const s = (serverName || '').toUpperCase();
  if (s.includes('VTMARKETS') || s.includes('VT-') || s.includes('VTM')) return { name: 'VTMarkets', color: '#00d4ff', accent: '#0066ff' };
  if (s.includes('RAISEFX') || s.includes('RAISE-') || s.includes('RAISEFX-')) return { name: 'RaiseFX', color: '#00ff88', accent: '#00ffaa' };
  if (s.includes('ICMARKETS') || s.includes('IC-')) return { name: 'IC Markets', color: '#ff6b00', accent: '#ff9500' };
  if (s.includes('VANTAGE') || s.includes('VANT-')) return { name: 'Vantage', color: '#ffd700', accent: '#ffaa00' };
  if (s.includes('EXNESS')) return { name: 'Exness', color: '#fbb900', accent: '#ff7700' };
  if (s.includes('FTMO')) return { name: 'FTMO', color: '#9b59b6', accent: '#8e44ad' };
  if (s.includes('PEPPERSTONE') || s.includes('PEPPER-')) return { name: 'Pepperstone', color: '#e74c3c', accent: '#c0392b' };
  if (s.includes('OANDA')) return { name: 'Oanda', color: '#0066cc', accent: '#004499' };
  if (s.includes('XM-') || s.includes('XMGLOBAL')) return { name: 'XM', color: '#e60000', accent: '#cc0000' };
  if (s.includes('ADMIRAL')) return { name: 'Admiral', color: '#1a5490', accent: '#0d3a6e' };
  if (s.includes('TICKMILL')) return { name: 'Tickmill', color: '#00a8e8', accent: '#0078a8' };
  if (s.includes('FXCM')) return { name: 'FXCM', color: '#00aa44', accent: '#008833' };
  if (s.includes('FUSION') || s.includes('FUSIONMARKETS')) return { name: 'Fusion Markets', color: '#7b68ee', accent: '#5a4ecc' };
  if (s.includes('FXPRO')) return { name: 'FxPro', color: '#003d99', accent: '#0066ff' };
  if (s.includes('FBS')) return { name: 'FBS', color: '#0099cc', accent: '#007fa8' };
  // Broker inconnu : on retourne le nom du serveur tel quel
  return { name: serverName || 'MT5 Broker', color: '#00f5ff', accent: '#00ff88' };
}

// ═══ ENDPOINTS MULTI-COMPTES MT5 ═══

// Liste tous les comptes MT5 du user (avec leur label, broker détecté, etc.)
app.get('/mt5/accounts', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  try {
    await migrateMT5Format(req.session.userId);
    const user = await db.findOneAsync({ _id: req.session.userId });
    const accounts = await getAllMT5Accounts(req.session.userId);
    const limit = getMT5AccountLimit(user);
    const activeId = user.activeMT5AccountId || (accounts[0] && accounts[0].id);

    res.json({
      accounts: accounts.map(a => ({
        id: a.id,
        label: a.label,
        login: a.login,
        server: a.server,
        accountType: a.accountType,
        balance: a.balance,
        credit: a.credit || 0,
        currency: a.currency,
        broker: detectBroker(a.server),
        isActive: a.id === activeId,
        addedAt: a.addedAt || a.connectedAt
      })),
      limit: limit,
      canAddMore: accounts.length < limit,
      activeId: activeId
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Switcher de compte actif
app.post('/mt5/accounts/switch', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  const { accountId } = req.body;
  if (!accountId) return res.status(400).json({ error: 'accountId requis' });
  try {
    await migrateMT5Format(req.session.userId);
    const accounts = await getAllMT5Accounts(req.session.userId);
    const target = accounts.find(a => a.id === accountId);
    if (!target) return res.status(404).json({ error: 'Compte introuvable' });

    // Update active + sync user.mt5 (rétrocompat)
    await db.updateAsync(
      { _id: req.session.userId },
      { $set: { activeMT5AccountId: accountId, mt5: target } }
    );
    // FIX multi-comptes : mettre à jour la session pour que les futures analyses
    // soient attribuées au bon compte
    req.session.userMT5AccountId = accountId;
    console.log('[MT5-SWITCH] User ' + req.session.userId + ' → compte ' + target.label);
    res.json({ success: true, account: target, broker: detectBroker(target.server) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Supprimer un compte de la liste
app.delete('/mt5/accounts/:accountId', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  const { accountId } = req.params;
  try {
    await migrateMT5Format(req.session.userId);
    const user = await db.findOneAsync({ _id: req.session.userId });
    const accounts = Array.isArray(user.mt5Accounts) ? user.mt5Accounts : [];
    const filtered = accounts.filter(a => a.id !== accountId);

    if (filtered.length === accounts.length) {
      return res.status(404).json({ error: 'Compte introuvable' });
    }

    // Si on supprimait le compte actif, on bascule sur le premier restant
    let newActive = user.activeMT5AccountId;
    let newMt5 = user.mt5;
    if (user.activeMT5AccountId === accountId) {
      newActive = filtered.length > 0 ? filtered[0].id : null;
      newMt5 = filtered.length > 0 ? filtered[0] : null;
    }

    await db.updateAsync(
      { _id: req.session.userId },
      { $set: {
        mt5Accounts: filtered,
        activeMT5AccountId: newActive,
        mt5: newMt5
      } }
    );
    console.log('[MT5-DELETE] User ' + req.session.userId + ' a supprimé compte ' + accountId);
    res.json({ success: true, remaining: filtered.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/mt5/status', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecte' });
  const user = await db.findOneAsync({ _id: req.session.userId });
  if (!user || !user.mt5) return res.json({ connected: false });
  const broker = detectBroker(user.mt5.server);
  res.json({
    connected: true,
    login: user.mt5.login,
    server: user.mt5.server,
    accountType: user.mt5.accountType,
    capital: user.mt5.capital,
    balance: user.mt5.balance || null,
    credit: user.mt5.credit || 0,
    equity: user.mt5.equity || null,
    currency: user.mt5.currency,
    profitFlottant: user.mt5.equity && user.mt5.balance ? +(user.mt5.equity - user.mt5.balance).toFixed(2) : 0,
    connectedAt: user.mt5.connectedAt,
    broker: broker
  });
});

// ─── GET /mt5/account-snapshot : info compte (cache, économe) ─────
// Renvoie balance/credit/equity stockés en DB (mis à jour à chaque refresh)
// Sans aucun deploy MetaApi → super rapide et gratuit
app.get('/mt5/account-snapshot', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  try {
    const user = await db.findOneAsync({ _id: req.session.userId });
    if (!user || !user.mt5) return res.json({ connected: false });
    const broker = detectBroker(user.mt5.server);
    const balance = parseFloat(user.mt5.balance) || 0;
    const credit = parseFloat(user.mt5.credit) || 0;
    const equity = parseFloat(user.mt5.equity) || balance;
    const profitFlottant = +(equity - balance - credit).toFixed(2);
    res.json({
      connected: true,
      broker: broker,
      login: user.mt5.login,
      server: user.mt5.server,
      balance: balance,
      credit: credit,
      equity: equity,
      profitFlottant: profitFlottant,
      currency: user.mt5.currency || 'USD',
      lastUpdate: user.mt5.lastBalanceUpdate || user.mt5.connectedAt
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── POST /mt5/refresh-capital : refresh capital depuis MT5 ─────────
// Deploy le compte temporairement pour recuperer le capital actuel
app.post('/mt5/refresh-capital', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  if (!metaApi) return res.status(500).json({ error: 'MetaApi non configuré' });
  const _u = await db.findOneAsync({ _id: req.session.userId });
  if (!hasPremiumAccess(_u)) return res.status(403).json({ error: 'mt5_plan_required', message: '🔒 Réservé aux plans Pro et Elite.' });
  const user = _u;
  if (!user || !user.mt5 || !user.mt5.metaApiAccountId) {
    return res.status(404).json({ error: 'MT5 non connecte' });
  }

  let _refreshAccount = null;
  let _refreshDeployedHere = false;
  try {
    _refreshAccount = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
    // FIX : vérifier l'état avant deploy — évite l'erreur 'already deployed'
    if (_refreshAccount.state === 'UNDEPLOYED') {
      await _refreshAccount.deploy();
      trackDeploy(_refreshAccount.id, user.mt5.login);
      _refreshDeployedHere = true;
      await _refreshAccount.waitConnected();
    }
    const connection = _refreshAccount.getRPCConnection();
    await connection.connect();
    await connection.waitSynchronized();
    const info = await connection.getAccountInformation();

    // FIX : undeploy seulement si c'est nous qui avons deployé
    if (_refreshDeployedHere) {
      await _refreshAccount.undeploy();
      trackUndeploy(_refreshAccount.id);
      _refreshDeployedHere = false;
    }

    // Capital effectif = balance + credit (bonus broker utilisable)
    const capitalEffectif = (parseFloat(info.balance) || 0) + (parseFloat(info.credit) || 0);

    await db.updateAsync(
      { _id: req.session.userId },
      { $set: {
        'mt5.capital': capitalEffectif,
        'mt5.balance': info.balance,
        'mt5.credit': info.credit || 0,
        'mt5.equity': info.equity || info.balance,
        'mt5.currency': info.currency,
        'mt5.lastBalanceUpdate': new Date().toISOString()
      } }
    );

    res.json({
      capital: capitalEffectif,
      balance: info.balance,
      credit: info.credit || 0,
      currency: info.currency
    });
  } catch (err) {
    // FIX : undeploy même en cas d'erreur pour éviter les fuites MetaAPI
    if (_refreshDeployedHere && _refreshAccount) {
      try { await _refreshAccount.undeploy(); trackUndeploy(_refreshAccount.id); } catch(e) {}
    }
    console.error('[MT5-REFRESH] Erreur:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── POST /mt5/place-order : placer un ordre LIMIT (deploy on-demand) ─
app.post('/mt5/place-order', checkPremium, async (req, res) => {
  if (!metaApi) return res.status(500).json({ error: 'MetaApi non configure' });

  const { symbol, direction, volume, entryPrice, sl, tp, analysisId, tp1, tp2, tp3, score } = req.body;
  if (!symbol || !direction || !volume || !entryPrice || !sl) {
    return res.status(400).json({ error: 'Donnees ordre incompletes' });
  }

  const user = await db.findOneAsync({ _id: req.session.userId });

  // ─── RESTRICTION PLAN : placement auto réservé Premium/Elite ────
  const planPO = (user && user.plan) ? user.plan.toLowerCase() : 'free';
  if (user && user.role !== 'admin' && !['premium', 'elite', 'pro', 'admin'].includes(planPO)) {
    return res.status(403).json({
      error: 'mt5_plan_required',
      message: 'Le placement automatique est réservé aux plans Premium et Elite.'
    });
  }

  if (!user || !user.mt5 || !user.mt5.metaApiAccountId) {
    return res.status(404).json({ error: 'MT5 non connecte. Connecte ton compte d\'abord.' });
  }

  // ─── COPIER L'ANALYSE DANS LA DB DU USER (pour TP partiel) ──────
  // Quand un user clique "ordre auto" sur une notif A+ partagée par un autre,
  // l'analyse n'existe pas dans SA DB → wrapper TP ne la trouve pas → pas de TP partiel.
  // → On créé une copie de l'analyse pour CE user pour activer le tracking TP.
  let analyseCopiee = null;
  try {
    let analyseSource = null;
    if (analysisId) {
      analyseSource = await analysesDb.findOneAsync({ _id: analysisId });
    }

    // Si analyse trouvée et qu'elle n'appartient pas déjà à ce user, la copier
    if (analyseSource && analyseSource.userId !== req.session.userId) {
      analyseCopiee = {
        _id: uuidv4(),
        userId: req.session.userId,
        instrument: symbol,
        decision: direction.toUpperCase(),
        entree: parseFloat(entryPrice),
        entry: parseFloat(entryPrice),
        sl: parseFloat(sl),
        tp1: tp1 || analyseSource.tp1 || tp || null,
        tp2: tp2 || analyseSource.tp2 || null,
        tp3: tp3 || analyseSource.tp3 || null,
        tp: tp || tp1 || analyseSource.tp1 || null,
        score: score || analyseSource.score || 8,
        lots: parseFloat(volume),
        createdAt: new Date(),
        // FIX FUITE METAAPI : marquer orderPlaced pour que le wrapper TP
        // sache qu'il y a un ordre à surveiller
        orderPlaced: true,
        placedAt: new Date().toISOString(),
        sourceFromAplusBroadcast: true,
        sourceAnalysisId: analysisId
      };
      await analysesDb.insertAsync(analyseCopiee);
      console.log('[MT5-ORDER] Analyse copiée pour user ' + req.session.userId + ' (source: ' + analysisId + ')');
    } else if (!analysisId && (tp1 || tp)) {
      // Pas d'analysisId fourni → créer une analyse pour le tracking
      analyseCopiee = {
        _id: uuidv4(),
        userId: req.session.userId,
        instrument: symbol,
        decision: direction.toUpperCase(),
        entree: parseFloat(entryPrice),
        entry: parseFloat(entryPrice),
        sl: parseFloat(sl),
        tp1: tp1 || tp || null,
        tp2: tp2 || null,
        tp3: tp3 || null,
        tp: tp || tp1 || null,
        score: score || 7,
        lots: parseFloat(volume),
        createdAt: new Date(),
        // FIX FUITE METAAPI : marqueur pour le wrapper TP
        orderPlaced: true,
        placedAt: new Date().toISOString(),
        sourceFromManualOrder: true
      };
      await analysesDb.insertAsync(analyseCopiee);
    } else if (analysisId && analyseSource && analyseSource.userId === req.session.userId) {
      // L'analyse appartient déjà au user → marquer orderPlaced=true sur elle directement
      try {
        await analysesDb.updateAsync(
          { _id: analysisId },
          { $set: { orderPlaced: true, placedAt: new Date().toISOString() } }
        );
      } catch(e) {}
    }
  } catch(copyErr) {
    console.log('[MT5-ORDER] Erreur copie analyse:', copyErr.message);
    // continue quand même : l'ordre sera placé, juste pas de TP partiel auto
  }

  let account;
  try {
    console.log('[MT5-ORDER] Place ' + direction + ' ' + symbol + ' ' + volume + ' lots @ ' + entryPrice);

    account = await metaApi.metatraderAccountApi.getAccount(user.mt5.metaApiAccountId);
    // FIX : ne deploy que si nécessaire — évite l'erreur 'already deployed'
    if (account.state === 'UNDEPLOYED') {
      await account.deploy();
      trackDeploy(account.id, user.mt5.login);
      await account.waitConnected();
    } else {
      trackDeploy(account.id, user.mt5.login); // tracker le compte même s'il était déjà deployed
    }

    const connection = account.getRPCConnection();
    await connection.connect();
    await connection.waitSynchronized();

    // Résolution unifiée selon serveur (priorité STD/VIP/ECN)
    const resolvedOrder = await resolveSymbolForUser(connection, symbol, user.mt5.server);
    if (!resolvedOrder) throw new Error('Symbole ' + symbol + ' introuvable sur ce broker (serveur ' + user.mt5.server + ').');
    const resolvedSymbol = resolvedOrder.symbol;
    const currentPrice = resolvedOrder.mid;
    console.log('[MT5-ORDER] Symbole resolu: ' + resolvedSymbol + ' (mid=' + currentPrice + ')');
    const isBuy = String(direction).toUpperCase().includes('BUY');

    // ═══════════════════════════════════════════════════════════════
    // 🎯 RÉ-AJUSTEMENT INTELLIGENT DE L'ENTRÉE AU MOMENT DU CLIC
    // ═══════════════════════════════════════════════════════════════
    // Entre l'analyse et le clic "ordre auto", le marché peut avoir bougé.
    // Si on place l'ordre tel quel, on risque d'avoir une entrée :
    //   - DÉJÀ DÉPASSÉE → BUY STOP loin sous le prix = ne sera jamais atteint
    //   - TROP LOIN → ordre LIMIT à 50$ du prix = on attend pour rien
    //
    // Stratégie de ré-ajustement :
    //   1. Calculer la distance entre entrée IA et prix actuel
    //   2. Si entrée encore valide (proche, du bon côté) → garder
    //   3. Si entrée dépassée mais le prix est près d'un niveau clé → MARKET au prix actuel
    //   4. Si entrée trop loin → ajuster l'entrée au plus proche niveau utile
    //   5. Toujours conserver la même DISTANCE SL pour préserver le R:R
    let entreeFinale = parseFloat(entryPrice);
    let slFinal = parseFloat(sl);
    let tpFinal = tp ? parseFloat(tp) : null;
    let entreeAjustee = false;
    let raisonAjustement = '';

    const distSLOriginal = Math.abs(entreeFinale - slFinal);
    // Tolérance XAU : 0.1% du prix (~$5 sur 4700) pour LIMIT, 0.05% pour STOP
    const tolerancePct = (resolvedSymbol.includes('XAU') || resolvedSymbol.includes('GOLD')) ? 0.001 : 0.0005;
    const tolerance = currentPrice * tolerancePct;

    // Vérifier si l'entrée est encore valide
    const entreeDepassee = isBuy ? entreeFinale < currentPrice - tolerance : entreeFinale > currentPrice + tolerance;
    const entreeTropLoin = Math.abs(entreeFinale - currentPrice) > tolerance * 50; // > 5% pour XAU = loin

    if (entreeDepassee) {
      // L'entrée IA est dépassée → on entre au MARKET au prix actuel
      // On déplace le SL pour conserver la même distance (donc même R:R)
      const oldEntree = entreeFinale;
      entreeFinale = currentPrice;
      slFinal = isBuy ? currentPrice - distSLOriginal : currentPrice + distSLOriginal;
      // Recalculer TP en conservant le R:R
      if (tpFinal) {
        const distTP = Math.abs(parseFloat(entryPrice) - parseFloat(tp));
        tpFinal = isBuy ? currentPrice + distTP : currentPrice - distTP;
      }
      entreeAjustee = true;
      raisonAjustement = `Entrée IA ${oldEntree.toFixed(2)} dépassée par le prix actuel ${currentPrice.toFixed(2)} → ré-ajusté au MARKET avec SL/TP recalculés`;
      console.log('[MT5-ORDER] ' + raisonAjustement);
    } else if (entreeTropLoin) {
      // L'entrée IA est trop loin → on annule (sécurité, pas de trade fantôme à 50$ de distance)
      console.log('[MT5-ORDER] Entrée ' + entreeFinale + ' trop loin du prix actuel ' + currentPrice.toFixed(2) + ' (>5%) → ordre annulé');
      try { await account.undeploy(); trackUndeploy(account.id); } catch(e) {}
      return res.status(400).json({
        error: 'entry_too_far',
        message: `L'entrée IA ${entreeFinale.toFixed(2)} est trop éloignée du prix actuel ${currentPrice.toFixed(2)} (>5%). Le marché a trop bougé. Refais une analyse.`
      });
    }

    // Détermine le type d'ordre final en fonction de l'entrée AJUSTÉE
    let orderType;
    if (entreeAjustee && Math.abs(entreeFinale - currentPrice) < tolerance) {
      // Entrée = prix actuel → MARKET ORDER (instantané)
      orderType = isBuy ? 'ORDER_TYPE_BUY' : 'ORDER_TYPE_SELL';
    } else if (isBuy) {
      orderType = entreeFinale < currentPrice ? 'ORDER_TYPE_BUY_LIMIT' : 'ORDER_TYPE_BUY_STOP';
    } else {
      orderType = entreeFinale > currentPrice ? 'ORDER_TYPE_SELL_LIMIT' : 'ORDER_TYPE_SELL_STOP';
    }

    console.log('[MT5-ORDER] Symbole final: ' + resolvedSymbol + ' | Type: ' + orderType + ' | Prix actuel: ' + currentPrice + ' | Entrée finale: ' + entreeFinale.toFixed(2) + (entreeAjustee ? ' (AJUSTÉE)' : ''));

    // Placer l'ordre avec le symbole resolu et l'entrée ajustée
    let result;
    if (orderType === 'ORDER_TYPE_BUY') {
      result = await connection.createMarketBuyOrder(resolvedSymbol, parseFloat(volume), slFinal, tpFinal, { comment: 'AIM' });
    } else if (orderType === 'ORDER_TYPE_SELL') {
      result = await connection.createMarketSellOrder(resolvedSymbol, parseFloat(volume), slFinal, tpFinal, { comment: 'AIM' });
    } else if (orderType === 'ORDER_TYPE_BUY_LIMIT') {
      result = await connection.createLimitBuyOrder(resolvedSymbol, parseFloat(volume), entreeFinale, slFinal, tpFinal, { comment: 'AIM' });
    } else if (orderType === 'ORDER_TYPE_BUY_STOP') {
      result = await connection.createStopBuyOrder(resolvedSymbol, parseFloat(volume), entreeFinale, slFinal, tpFinal, { comment: 'AIM' });
    } else if (orderType === 'ORDER_TYPE_SELL_LIMIT') {
      result = await connection.createLimitSellOrder(resolvedSymbol, parseFloat(volume), entreeFinale, slFinal, tpFinal, { comment: 'AIM' });
    } else if (orderType === 'ORDER_TYPE_SELL_STOP') {
      result = await connection.createStopSellOrder(resolvedSymbol, parseFloat(volume), entreeFinale, slFinal, tpFinal, { comment: 'AIM' });
    }

    console.log('[MT5-ORDER] Ordre place ! ID:', result.orderId);

    // ═══ FIX BUG TP PARTIEL : Créer le tracking IMMÉDIATEMENT ═══
    // Avant : le tracking n'était créé QUE par le wrapper TP au prochain cycle (5 min).
    // Si le TP1 était touché avant ces 5 min → on ratait le BE et le TP partiel.
    // Maintenant : tracking créé dès le placement → wrapper TP a tout en main au 1er passage.
    try {
      const analyseTracking = analyseCopiee || (analysisId ? await analysesDb.findOneAsync({ _id: analysisId }) : null);
      if (analyseTracking) {
        const trackingExistant = await positionsTrackingDb.findOneAsync({
          userId: req.session.userId,
          orderId: result.orderId
        });
        if (!trackingExistant) {
          // Récupérer la distribution selon le score (40/30/30, 50/50, etc.)
          const distribution = typeof getDistribution === 'function'
            ? getDistribution(analyseTracking.score || 7)
            : { tp1: 0.5, tp2: 0.3, tp3: 0.2, mode: 'A' };

          // FIX : pour MARKET ORDER, orderId == positionId généralement
          // Pour LIMIT ORDER, positionId créé à l'exécution → on initialise à orderId
          // Le wrapper TP va matcher via positionId, donc on doit le renseigner
          await positionsTrackingDb.insertAsync({
            _id: uuidv4(),
            userId: req.session.userId,
            orderId: result.orderId,
            positionId: result.orderId, // Initialement = orderId (sera mis à jour si différent)
            analyseId: analyseTracking._id,
            symbol: resolvedSymbol,
            direction: direction.toUpperCase(),
            entree: parseFloat(entreeFinale),
            entry: parseFloat(entreeFinale), // alias pour compatibilité wrapper
            sl: parseFloat(slFinal),
            tp1: analyseTracking.tp1 ? parseFloat(analyseTracking.tp1) : null,
            tp2: analyseTracking.tp2 ? parseFloat(analyseTracking.tp2) : null,
            tp3: analyseTracking.tp3 ? parseFloat(analyseTracking.tp3) : null,
            score: analyseTracking.score || 7,
            volumeInitial: parseFloat(volume),
            volumeRestant: parseFloat(volume),
            tp1Volume: 0,
            tp2Volume: 0,
            distribution: distribution,
            miTp1Done: false,
            miTp2Done: false,
            tp1Done: false,
            tp2Done: false,
            tp3Done: false,
            beDone: false,
            createdAt: new Date(),
            sourceTracking: 'immediate_placement'
          });
          console.log('[TRACKING-IMMEDIAT] Position ' + result.orderId + ' tracée immédiatement (score ' + (analyseTracking.score || 7) + ', mode ' + distribution.mode + ')');
        }
      }
    } catch(trackErr) {
      console.log('[TRACKING-IMMEDIAT] Erreur création tracking:', trackErr.message);
      // Pas bloquant : si le tracking immédiat échoue, le wrapper rattrapera plus tard
    }

    await account.undeploy();
    trackUndeploy(account.id);

    // FIX COÛT : 4 déclenchements c'est trop, on en garde QUE 1 à 60s
    // Le tracking est déjà créé immédiatement avec orderId et positionId,
    // donc le prochain cycle wrapper (toutes les 10min) le retrouvera.
    // Un seul trigger à 60s pour rattraper les TP1 très rapides (rare sur XAU).
    setTimeout(() => {
      gererTpPartielsWrapper().catch(e => console.log('[TP-IMMEDIAT-60s]', e.message));
    }, 60 * 1000);

    res.json({
      success: true,
      orderId: result.orderId,
      orderType,
      entreeAjustee,
      raisonAjustement,
      entreeFinale: entreeFinale.toFixed(2),
      slFinal: slFinal.toFixed(2),
      tpFinal: tpFinal ? tpFinal.toFixed(2) : null,
      message: entreeAjustee
        ? 'Ordre place ✓ — Entrée ajustée au prix actuel (' + currentPrice.toFixed(2) + ')'
        : 'Ordre place sur ton MT5 ✓'
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

app.listen(port, () => {
  console.log('✅ Serveur lancé sur http://localhost:' + port);
  console.log('   Mode :', process.env.NODE_ENV || 'development');
  console.log('   PID  :', process.pid);
});