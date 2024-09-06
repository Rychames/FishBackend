    const express = require('express');
    const bodyParser = require('body-parser');
    const mysql = require('mysql2');
    const bcrypt = require('bcrypt');
    const jwt = require('jsonwebtoken');

    const app = express();
    const port = 3000;

    app.use(bodyParser.json());

    // Configuração da conexão com o banco de dados
    const db = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'root',
        database: 'FishConnect'
    });

    db.connect((err) => {
        if (err) throw err;
        console.log('Conectado ao banco de dados');
    });

    // Rota de cadastro
    app.post('/register', (req, res) => {
        const { username, password, email, number_telephone } = req.body;

        // Verifica se o email já está em uso
        const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
        db.query(checkEmailQuery, [email], (err, result) => {
            if (err) throw err;
            if (result.length > 0) {
                return res.status(400).json({ message: 'Email já cadastrado' });
            }

            // Hash da senha e inserção no banco de dados
            bcrypt.hash(password, 10, (err, hash) => {
                if (err) throw err;
                const insertUserQuery = `
                    INSERT INTO users (username, user_password, email, number_telephone, created_at)
                    VALUES (?, ?, ?, ?, NOW())
                `;
                db.query(insertUserQuery, [username, hash, email, number_telephone], (err, result) => {
                    if (err) throw err;
                    res.status(201).json({ message: 'Usuário registrado com sucesso' });
                });
            });
        });
    });

    // Rota de login
    app.post('/login', (req, res) => {
        const { email, password } = req.body;

        const findUserQuery = 'SELECT * FROM users WHERE email = ?';
        db.query(findUserQuery, [email], (err, result) => {
            if (err) throw err;
            if (result.length === 0) {
                return res.status(400).json({ message: 'Email ou senha incorretos' });
            }

            const user = result[0];
            bcrypt.compare(password, user.user_password, (err, isMatch) => {
                if (err) throw err;
                if (!isMatch) {
                    return res.status(400).json({ message: 'Email ou senha incorretos' });
                }

                // Gerar token JWT
                const token = jwt.sign({ id: user.id, email: user.email }, 'seu_segredo', { expiresIn: '1h' });
                res.json({ message: 'Login realizado com sucesso', token });
            });
        });
    });

    app.listen(port, () => {
        console.log(`Servidor rodando na porta ${port}`);
    });
