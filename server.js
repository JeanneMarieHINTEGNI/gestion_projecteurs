const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const connection = require('./db'); // Assurez-vous que ce fichier est correctement configuré.

dotenv.config();
const app = express();
app.use(express.json());

// Middleware pour vérifier les rôles
const authorizeAdmin = (req, res, next) => {
    if (req.user.role !== 'administrateur') {
        return res.status(403).json({ message: 'Accès refusé, rôle insuffisant.' });
    }
    next();
};

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

// Route d'inscription
app.post('/register', async (req, res) => {
    const { email, password, role = 'étudiant' } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email et mot de passe sont requis.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        connection.query('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [email, hashedPassword, role], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ message: 'Utilisateur créé avec succès!' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la création de l\'utilisateur.' });
    }
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
        message: `Bienvenue, utilisateur ${req.user.id}!`, 
        role: req.user.role 
    });
});

// Route protégée pour ajouter un projecteur
app.post('/projectors', authenticateJWT, authorizeAdmin, (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ message: 'Le nom du projecteur est requis.' });

    connection.query('INSERT INTO projectors (name) VALUES (?)', [name], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: 'Projecteur ajouté!' });
    });
});

// Route pour modifier un projecteur
app.put('/projectors/:id', authenticateJWT, authorizeAdmin, (req, res) => {
    const { id } = req.params;
    const { name, available } = req.body;

    if (!id || !name) {
        return res.status(400).json({ message: 'ID et nom requis.' });
    }

    connection.query('UPDATE projectors SET name = ?, available = ? WHERE id = ?', [name, available, id], (err) => {
        if (err) {
            console.error('Erreur lors de la modification:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Projecteur modifié avec succès!' });
    });
});

// Route pour supprimer un projecteur
app.delete('/projectors/:id', authenticateJWT, authorizeAdmin, (req, res) => {
    const { id } = req.params;

    if (!id) {
        return res.status(400).json({ message: 'ID requis.' });
    }

    connection.query('DELETE FROM projectors WHERE id = ?', [id], (err) => {
        if (err) {
            console.error('Erreur lors de la suppression:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Projecteur supprimé avec succès!' });
    });
});

// Réserver un projecteur
app.post('/reservations', authenticateJWT, (req, res) => {
    const { projector_id, startTime, endTime } = req.body;

    if (!projector_id || !startTime || !endTime) {
        return res.status(400).json({ message: 'Tous les champs sont requis.' });
    }

    connection.query('SELECT available FROM projectors WHERE id = ?', [projector_id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });

        if (results.length === 0 || !results[0].available) {
            return res.status(400).json({ message: 'Projecteur indisponible!' });
        }

        connection.query('SELECT * FROM reservations WHERE projector_id = ? AND ((startTime < ? AND endTime > ?) OR (startTime < ? AND endTime > ?))',
            [projector_id, endTime, endTime, startTime, startTime], (err, results) => {
                if (err) return res.status(500).json({ error: err.message });

                if (results.length > 0) {
                    return res.status(400).json({ message: 'Conflit de réservation!' });
                }

                connection.query('INSERT INTO reservations (user_id, projector_id, reservation_date, startTime, endTime) VALUES (?, ?, NOW(), ?, ?)', 
                [req.user.id, projector_id, startTime, endTime], (err) => {
                    if (err) return res.status(500).json({ error: err.message });

                    connection.query('UPDATE projectors SET available = FALSE WHERE id = ?', [projector_id], (err) => {
                        if (err) return res.status(500).json({ error: err.message });
                        res.status(201).json({ message: 'Réservation créée!' });
                    });
                });
            });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Le serveur écoute sur le port ${PORT}`);
});