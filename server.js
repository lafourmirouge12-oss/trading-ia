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

// --- 1. CONFIGURATION BASE DE DONNÉES ---
const db = new Datastore({ filename: 'users.db', autoload: true });

// --- 2. CONFIGURATION MOTEUR DE RENDU & DOSSIERS ---
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- 3. CONFIGURATION SESSION ---
app.use(session({
    secret: process.env.SESSION_SECRET || 'cyber-trading-secret-ultra-secure',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // Session de 24 heures
}));

// --- 4. CONFIGURATION NODEMAILER (GMAIL) ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'lafourmirouge12@gmail.com',
        pass: process.env.GMAIL_PASS 
    }
});

// --- 5. LE GARDE DU CORPS (MIDDLEWARE DE SÉCURITÉ) ---
function checkAuth(req, res, next) {
    if (req.session.userId) {
        next(); // L'utilisateur est connecté, on le laisse passer
    } else {
        res.redirect('/login'); // Pas connecté, retour à la case départ
    }
}

// --- 6. ROUTES DE NAVIGATION ---

// L'accueil décide si on va au dashboard ou au login
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

// ROUTE PROTÉGÉE : Personne ne peut entrer sans checkAuth
app.get('/dashboard', checkAuth, (req, res) => {
    res.render('admin'); 
});

// --- 7. SYSTÈME D'INSCRIPTION & EMAIL ---

app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    
    db.findOne({ email }, async (err, user) => {
        if (user) return res.json({ error: "Cet email est déjà utilisé" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = uuidv4();

        const newUser = {
            email,
            password: hashedPassword,
            isVerified: false,
            verificationToken,
            role: 'user',
            createdAt: new Date()
        };

        db.insert(newUser, (err, savedUser) => {
            const verificationLink = `${process.env.BASE_URL}/verify/${verificationToken}`;
            
            const mailOptions = {
                from: 'lafourmirouge12@gmail.com',
                to: email,
                subject: 'Activez votre compte Trading IA',
                html: `<h1>BIENVENUE AGENT</h1><p>Cliquez ici : <a href="${verificationLink}">VÉRIFIER MON COMPTE</a></p>`
            };

            transporter.sendMail(mailOptions, (error) => {
                if (error) return res.json({ error: "Erreur email" });
                res.json({ success: "Compte créé ! Vérifiez vos emails." });
            });
        });
    });
});

// --- 8. SYSTÈME DE CONNEXION ---

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.findOne({ email }, async (err, user) => {
        if (!user) return res.json({ error: "Utilisateur non trouvé" });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.json({ error: "Mot de passe incorrect" });

        if (!user.isVerified) {
            return res.json({ error: "Veuillez vérifier votre email" });
        }

        // Création de la session
        req.session.userId = user._id;
        req.session.role = user.role;
        res.json({ redirect: '/dashboard' });
    });
});

// --- 9. VÉRIFICATION ET RENVOI ---

app.get('/verify/:token', (req, res) => {
    const { token } = req.params;
    db.update({ verificationToken: token }, { $set: { isVerified: true } }, {}, (err, numUpdated) => {
        if (numUpdated === 0) return res.send("Lien invalide.");
        res.render('success');
    });
});

app.post('/resend-email', (req, res) => {
    const { email } = req.body;
    db.findOne({ email }, (err, user) => {
        if (!user || user.isVerified) return res.json({ error: "Impossible de renvoyer" });
        const verificationLink = `${process.env.BASE_URL}/verify/${user.verificationToken}`;
        transporter.sendMail({
            from: 'lafourmirouge12@gmail.com',
            to: email,
            subject: 'Renvoyer : Activation',
            html: `<p><a href="${verificationLink}">Cliquez ici</a></p>`
        }, () => res.json({ success: "Email renvoyé !" }));
    });
});

// --- LOGOUT ---
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.listen(port, () => {
    console.log(`Serveur sécurisé sur le port ${port}`);
});