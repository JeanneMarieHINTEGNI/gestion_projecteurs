
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();
const connection = require('./db');

dotenv.config();
const app = express();
app.use(express.json());

// Route d'inscription
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    connection.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: 'Utilisateur créé avec succès!' });
    });
});

// Route de connexion
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    connection.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error(err); // Ajouter la journalisation d'erreurs
            return res.status(500).json({ error: err.message });
        }
        if (results.length === 0) return res.status(404).json({ message: 'Utilisateur non trouvé!' });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Mot de passe incorrect!' });

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
        res.json({ token });
    });
});

// Middleware d'authentification
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(403); // Pas de token, accès refusé

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Token invalide, accès refusé
        req.user = user;
        next();
    });
};

// Route protégée
app.get('/profile', authenticateJWT, (req, res) => {
    res.json({ message: `Bienvenue, utilisateur ${req.user.id}!`, role: req.user.role });
});

// Démarrer le serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Le serveur écoute sur le port ${PORT}`);
});

// Ajouter un projecteur
app.post('/projectors', authenticateJWT, (req, res) => {
    const { name } = req.body;
    connection.query('INSERT INTO projectors (name) VALUES (?)', [name], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: 'Projecteur ajouté!' });
    });
});

// Lister les projecteurs
app.get('/projectors', authenticateJWT, (req, res) => {
    connection.query('SELECT * FROM projectors', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// Modifier un projecteur
app.put('/projectors/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const { available } = req.body;
    connection.query('UPDATE projectors SET available = ? WHERE id = ?', [available, id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Projecteur modifié!' });
    });
});

// Supprimer un projecteur
app.delete('/projectors/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    connection.query('DELETE FROM projectors WHERE id = ?', [id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Projecteur supprimé!' });
    });
});

// Réserver un projecteur
app.post('/reservations', authenticateJWT, (req, res) => {
    const { projectorId, startTime, endTime } = req.body;
    connection.query('INSERT INTO reservations (userId, projectorId, startTime, endTime) VALUES (?, ?, ?, ?)', 
    [req.user.id, projectorId, startTime, endTime], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: 'Réservation créée!' });
    });
});

// Lister les réservations
app.get('/reservations', authenticateJWT, (req, res) => {
    connection.query('SELECT * FROM reservations WHERE userId = ?', [req.user.id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// Annuler une réservation
app.delete('/reservations/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    connection.query('DELETE FROM reservations WHERE id = ?', [id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Réservation annulée!' });
    });
});
console.log('Clé secrète JWT:', process.env.JWT_SECRET); // Ajoutez cette ligne pour le débogage