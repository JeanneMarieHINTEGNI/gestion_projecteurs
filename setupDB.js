
const connection = require('./db');

const createTables = () => {
    const usersTable = `CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('etudiant', 'enseignant', 'administrateur') DEFAULT 'etudiant'
    )`;

    const projectorsTable = `CREATE TABLE IF NOT EXISTS projectors (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        available BOOLEAN DEFAULT TRUE
    )`;

    const reservationsTable = `CREATE TABLE IF NOT EXISTS reservations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        userId INT,
        projectorId INT,
        startTime DATETIME,
        endTime DATETIME,
        FOREIGN KEY (userId) REFERENCES users(id),
        FOREIGN KEY (projectorId) REFERENCES projectors(id)
    )`;

    connection.query(usersTable, (err) => {
        if (err) throw err;
    });

    connection.query(projectorsTable, (err) => {
        if (err) throw err;
    });

    connection.query(reservationsTable, (err) => {
        if (err) throw err;
    });

    console.log('Tables créées!');
    connection.end();
};

createTables();