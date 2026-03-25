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

// --- CONFIGURATION ---
const db = new Datastore({ filename: 'users.db', autoload: true });
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ATTENTION : Ne mets JAMAIS 'views' dans express.static, sinon n'importe qui accède aux fichiers !
app.use(express.static('public')); 
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'cyber-trading-secret-999',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: 'lafourmirouge12@gmail.com', pass: process.env.GMAIL_PASS }
});

// --- LE GARDE DU CORPS (MIDDLEWARE) ---
function checkAuth(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    // Si pas de session, on redirige vers le login avec le signal d'alerte
    res.redirect('/login?auth=failed');
}

// --- ROUTES DE NAVIGATION (LES SEULES ET UNIQUES) ---

// 1. La racine '/' : Elle redirige FORCÉMENT soit vers le dashboard, soit vers le login
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

// 2. La page Login
app.get('/login', (req, res) => {
    res.render('login');
});

// 3. La page Register
app.get('/register', (req, res) => {
    res.render('register');
});

// 4. Le Dashboard (PROTÉGÉ PAR checkAuth)
app.get('/dashboard', checkAuth, (req, res) => {
    res.render('admin'); // Affiche ton fichier admin.ejs
});

// 5. La Déconnexion
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// --- SYSTÈME AUTHENTIFICATION (API) ---

app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    db.findOne({ email }, async (err, user) => {
        if (user) return res.json({ error: "Email déjà utilisé" });
        const hashedPassword = await bcrypt.hash(password, 10);
        const token = uuidv4();
        db.insert({ email, password: hashedPassword, isVerified: false, verificationToken: token }, (err) => {
            const link = `${process.env.BASE_URL}/verify/${token}`;
            transporter.sendMail({
                from: 'lafourmirouge12@gmail.com',
                to: email,
                subject: 'Activation Trading IA',
                html: `<p>Cliquez ici pour activer : <a href="${link}">${link}</a></p>`
            }, () => res.json({ success: "Vérifiez vos emails !" }));
        });
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.findOne({ email }, async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.json({ error: "Identifiants incorrects" });
        }
        if (!user.isVerified) return res.json({ error: "Veuillez vérifier votre email" });
        
        // On enregistre l'ID dans la session
        req.session.userId = user._id;
        res.json({ redirect: '/dashboard' });
    });
});

app.get('/verify/:token', (req, res) => {
    db.update({ verificationToken: req.params.token }, { $set: { isVerified: true } }, {}, (err, num) => {
        num > 0 ? res.render('success') : res.send("Lien expiré ou invalide");
    });
});

app.listen(port, () => console.log(`Serveur prêt sur le port ${port}`));