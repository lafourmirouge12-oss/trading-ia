require('dotenv').config();
const express = require('express');
const session = require('express-session');
const Datastore = require('@seald-io/nedb');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = process.env.PORT || 3000;

const db = new Datastore({ filename: 'users.db', autoload: true });
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static('public')); 
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'cyber-trading-ultra-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: 'lafourmirouge12@gmail.com', pass: process.env.GMAIL_PASS }
});

// MIDDLEWARE SECURITÉ
function checkAuth(req, res, next) {
    if (req.session && req.session.userId) return next();
    res.redirect('/login?auth=failed');
}

// --- ROUTES NAVIGATION ---

app.get('/', (req, res) => {
    req.session.userId ? res.redirect('/dashboard') : res.redirect('/login');
});

app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

// DASHBOARD
app.get('/dashboard', checkAuth, (req, res) => {
    res.render('admin'); 
});

// PAGE ABONNEMENT (Anciennement dans public)
app.get('/abonnement', checkAuth, (req, res) => {
    res.render('abonnement'); 
});

// --- LOGIQUE DES 2 ANALYSES ---

app.post('/analyze', checkAuth, (req, res) => {
    const userId = req.session.userId;

    db.findOne({ _id: userId }, (err, user) => {
        // Si l'utilisateur n'a pas de compteur, on le met à 0
        let count = user.analysisCount || 0;

        if (count >= 2 && user.role !== 'premium') {
            // BLOQUÉ : Trop d'analyses
            return res.json({ redirect: '/abonnement', error: "Limite de 2 analyses gratuite atteinte." });
        }

        // --- ICI TON CODE D'ANALYSE IA ---
        // Simulons une réponse de l'IA
        const aiResponse = "Analyse terminée : Tendance Haussière détectée.";

        // On augmente le compteur de +1
        db.update({ _id: userId }, { $set: { analysisCount: count + 1 } }, {}, () => {
            res.json({ success: aiResponse, count: count + 1 });
        });
    });
});

// --- AUTHENTIFICATION ---

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.findOne({ email }, async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.json({ error: "Identifiants incorrects" });
        }
        if (!user.isVerified) return res.json({ error: "Vérifiez votre email" });
        
        req.session.userId = user._id;
        res.json({ redirect: '/dashboard' });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

// Inscription et Vérification (Identique au précédent)
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = uuidv4();
    db.insert({ email, password: hashedPassword, isVerified: false, verificationToken: token, analysisCount: 0, role: 'user' }, (err) => {
        const link = `${process.env.BASE_URL}/verify/${token}`;
        transporter.sendMail({ from: 'lafourmirouge12@gmail.com', to: email, subject: 'Activation IA', html: `<a href="${link}">Activer</a>` }, 
        () => res.json({ success: "Mail envoyé" }));
    });
});

app.get('/verify/:token', (req, res) => {
    db.update({ verificationToken: req.params.token }, { $set: { isVerified: true } }, {}, () => res.render('success'));
});

app.listen(port, () => console.log(`🚀 Terminal en ligne sur le port ${port}`));