
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const connection = require('./db');

dotenv.config();
const app = express();
app.use(express.json());


// Middleware d'authentification
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(403);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};


Copier
// Middleware pour vérifier les rôles
const authorizeAdmin = (req, res, next) => {
    if (req.user.role !== 'administrateur') {
        return res.status(403).json({ message: 'Accès refusé, rôle insuffisant.' });
    }
    next();
};


// Route d'inscription
app.post('/register', async (req, res) => {
    const { email, password, role = 'étudiant' } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    connection.query('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [email, hashedPassword, role], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: 'Utilisateur créé avec succès!' });
    });
});

// Route de connexion
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    connection.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ message: 'Utilisateur non trouvé!' });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Mot de passe incorrect!' });

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
        res.json({ token });
    });
});

// Route protégée pour obtenir le profil de l'utilisateur
app.get('/profile', authenticateJWT, (req, res) => {
    res.json({ 
        message: 'Bienvenue, utilisateur ${req.user.id}!', 
        role: req.user.role 
    });
});

// Exemple de route protégée pour les administrateurs
app.post('/projectors', authenticateJWT, authorizeAdmin, (req, res) => {
    const { name } = req.body;
    connection.query('INSERT INTO projectors (name) VALUES (?)', [name], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: 'Projecteur ajouté!' });
    });
});

// Réserver un projecteur
app.post('/reservations', authenticateJWT, (req, res) => {
    const { projectorId, startTime, endTime } = req.body;

    // Vérifier la disponibilité du projecteur
    connection.query('SELECT available FROM projectors WHERE id = ?', [projectorId], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0 || !results[0].available) {
            return res.status(400).json({ message: 'Projecteur indisponible!' });
        }

        connection.query('INSERT INTO reservations (userId, projectorId, startTime, endTime) VALUES (?, ?, ?, ?)', 
        [req.user.id, projectorId, startTime, endTime], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ message: 'Réservation créée!' });
        });
    });
});



const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log('Le serveur écoute sur le port ${PORT}');
});
