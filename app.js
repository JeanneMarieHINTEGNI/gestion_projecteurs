
const express = require('express');
const db = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Route pour ajouter un utilisateur
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, result) => {
        if (err) return res.status(500).send(err);
        res.status(201).send('Utilisateur créé avec succès');
    });
});

// Route pour récupérer tous les projecteurs
app.get('/projectors', (req, res) => {
    db.query('SELECT * FROM projectors', (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

app.listen(PORT, () => {
    console.log(`Serveur en écoute sur le port ${PORT}`);
});