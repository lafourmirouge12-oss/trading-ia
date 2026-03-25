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

// --- CONFIGURATION BASE DE DONNÉES ---
const db = new Datastore({ filename: 'users.db', autoload: true });

// --- CONFIGURATION MOTEUR DE RENDU ---
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- CONFIGURATION SESSION ---
app.use(session({
    secret: process.env.SESSION_SECRET || 'cyber-trading-secret',
    resave: false,
    saveUninitialized: false
}));

// --- CONFIGURATION NODEMAILER (GMAIL) ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'lafourmirouge12@gmail.com',
        pass: process.env.GMAIL_PASS 
    }
});

// --- ROUTE : INSCRIPTION (REGISTER) ---
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
                html: `
                    <div style="background:#050505; color:white; padding:20px; border:1px solid #00f3ff; font-family:sans-serif;">
                        <h1 style="color:#00f3ff;">BIENVENUE AGENT</h1>
                        <p>Cliquez sur le lien ci-dessous pour confirmer votre accès au terminal :</p>
                        <a href="${verificationLink}" style="display:inline-block; padding:10px 20px; background:#00f3ff; color:black; text-decoration:none; font-weight:bold;">VÉRIFIER MON COMPTE</a>
                    </div>`
            };

            transporter.sendMail(mailOptions, (error) => {
                if (error) return res.json({ error: "Erreur lors de l'envoi de l'email" });
                res.json({ success: "Compte créé ! Vérifiez vos emails (et spams)." });
            });
        });
    });
});

// --- ROUTE : CONNEXION (LOGIN) ---
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.findOne({ email }, async (err, user) => {
        if (!user) return res.json({ error: "Utilisateur non trouvé" });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.json({ error: "Mot de passe incorrect" });

        if (!user.isVerified) {
            return res.json({ error: "Veuillez vérifier votre email avant de vous connecter" });
        }

        req.session.userId = user._id;
        req.session.role = user.role;
        res.json({ redirect: '/dashboard' });
    });
});

// --- ROUTE : RENVOYER L'EMAIL ---
app.post('/resend-email', (req, res) => {
    const { email } = req.body;

    db.findOne({ email }, (err, user) => {
        if (!user) return res.json({ error: "Email inconnu" });
        if (user.isVerified) return res.json({ error: "Compte déjà vérifié" });

        const verificationLink = `${process.env.BASE_URL}/verify/${user.verificationToken}`;
        
        const mailOptions = {
            from: 'lafourmirouge12@gmail.com',
            to: email,
            subject: 'Renvoyer : Activation de votre compte',
            html: `<p>Nouveau lien de vérification : <a href="${verificationLink}">Cliquez ici</a></p>`
        };

        transporter.sendMail(mailOptions, (error) => {
            if (error) return res.json({ error: "Erreur d'envoi" });
            res.json({ success: "Un nouvel email a été envoyé !" });
        });
    });
});

// --- ROUTE : VÉRIFICATION DU LIEN ---
app.get('/verify/:token', (req, res) => {
    const { token } = req.params;
    db.update({ verificationToken: token }, { $set: { isVerified: true } }, {}, (err, numUpdated) => {
        if (numUpdated === 0) return res.send("Lien invalide ou expiré.");
        res.render('success', { message: "Votre compte a été activé avec succès !" });
    });
});

// --- ROUTES PAGES ---
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));
app.get('/dashboard', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.render('admin'); // Ou ta page dashboard
});

app.listen(port, () => {
    console.log(`Serveur lancé sur http://localhost:${port}`);
});