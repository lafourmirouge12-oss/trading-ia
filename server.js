const express = require('express');
const session = require('express-session');
const Datastore = require('@seald-io/nedb'); // <--- Utilise bien le nom complet avec @seald-io
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
// Sur Render, le chemin doit être absolu pour éviter les erreurs d'écriture
const db = new Datastore({ filename: path.join(__dirname, 'users.db'), autoload: true });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'trading_secret_key_123',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// --- CONFIGURATION EMAIL ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'lafourmirouge12@gmail.com',
        pass: 'jvltzfyyvgmfycpg' // <--- METS TES 16 LETTRES ICI
    }
});

// --- DÉFINITION DE L'URL RENDER ---
// Remplace 'ton-app-trading' par le nom exact de ton projet sur Render
const BASE_URL = "https://trading-clean.onrender.com"; 

// --- ROUTES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

// --- INSCRIPTION ---
app.post('/register', (req, res) => {
    const { email, password } = req.body;
    db.findOne({ email }, (err, user) => {
        if (user) return res.json({ error: "Email déjà utilisé" });

        const newUser = {
            email,
            password, 
            role: 'user',
            currentDevice: req.headers['user-agent'],
            lastDeviceChange: new Date()
        };

        db.insert(newUser, (err) => {
            if (err) return res.json({ error: "Erreur base de données" });
            
            transporter.sendMail({
                from: '"Trading IA" <lafourmirouge12@gmail.com>',
                to: email,
                subject: 'Bienvenue chez Trading IA',
                html: `<h2>Compte créé !</h2>
                       <p>Votre appareil est enregistré.</p>
                       <p><a href="${BASE_URL}/login">Cliquez ici pour vous connecter</a></p>`
            });
            res.json({ success: "Compte créé ! Vérifiez votre email." });
        });
    });
});

// --- RENVOI EMAIL ---
app.post('/resend-email', (req, res) => {
    const { email } = req.body;
    db.findOne({ email }, (err, user) => {
        if (!user) return res.json({ error: "Aucun compte trouvé." });

        transporter.sendMail({
            from: '"Trading IA" <lafourmirouge12@gmail.com>',
            to: email,
            subject: 'Renvoi : Confirmation de compte',
            html: `<h2>Lien de connexion</h2>
                   <p>Accédez à votre compte ici :</p>
                   <a href="${BASE_URL}/login">Se connecter</a>`
        }, (err) => {
            if (err) return res.json({ error: "Erreur d'envoi." });
            res.json({ success: "Email renvoyé avec succès !" });
        });
    });
});

// --- CONNEXION (30 JOURS) ---
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const device = req.headers['user-agent'];

    db.findOne({ email }, (err, user) => {
        if (!user || user.password !== password) return res.json({ error: "Identifiants incorrects" });

        if (user.role === 'admin') {
            req.session.isAdmin = true;
            return res.json({ success: true, redirect: '/admin' });
        }

        const thirtyDays = 30 * 24 * 60 * 60 * 1000;
        const now = new Date();

        if (user.currentDevice && user.currentDevice !== device) {
            const diff = now - new Date(user.lastDeviceChange);
            if (diff < thirtyDays) {
                const rest = Math.ceil((thirtyDays - diff) / (1000 * 60 * 60 * 24));
                return res.json({ error: `Nouvel appareil. Attendez ${rest} jours.` });
            }
        }

        db.update({ _id: user._id }, { $set: { currentDevice: device, lastDeviceChange: now } });
        req.session.userId = user._id;
        res.json({ success: true, redirect: '/' });
    });
});

// --- ADMIN ---
app.get('/admin', (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send("Refusé");
    db.find({}, (err, users) => res.render('admin', { users }));
});

// Port dynamique pour Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur en ligne sur le port ${PORT}`));