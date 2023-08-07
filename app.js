require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// Config JSON
app.use(express.json());
app.use(cors());

// Models
const User = require('./models/User');

// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: "Bem vindo a nossa API" })
});

// Private Route
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    // check if user exists
    const user = await User.findById(id, '-password');

    if(!user) {
        return res.status(404).json({ msg: "Usuário não encontrado"});
    }

    res.status(200).json({ user });
});

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if(!token) {
        return res.status(401).json({ msg: 'Acesso negado'});
    }

    try {
        const secret = process.env.SECRET;

        jwt.verify(token, secret);

        next();
    } catch (error) {
        res.status(400).json({ msg: 'Token inválido' });
    }
}

// Register User - Public Route
app.post('/auth/user', async (req, res) => {
    const { name, email, password, phone } = req.body;

    if (!name) {
        return res.status(422).json({ msg: "O nome é obrigatório" });
    }

    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório" });
    }

    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória" });
    }

    if (!phone) {
        return res.status(422).json({ msg: "O telefone é obrigatório" });
    }

    // check if email exists
    const userExists = await User.findOne({ email: email });

    if (userExists) {
        return res.status(422).json({ msg: "Email já cadastrado" })
    }

    // create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // create user
    const user = new User({
        name,
        email,
        phone,
        password: passwordHash
    });

    try {
        await user.save();
        res.status(201).json({ msg: 'Usuário criado' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Erro no servidor, tente novamente mais tarde" });
    }

});


// Login User
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório" });
    }

    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória" });
    }

    // check if user exists
    const user = await User.findOne({ email: email });

    if (!user) {
        return res.status(422).json({ msg: "Usuário não cadastrado" });
    }

    // check if password matches
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida" });
    }

    try {
        const secret = process.env.SECRET;
        const expiresInMinutes = 30;
        const token = jwt.sign(
            { id: user._id },
            secret,
            { expiresIn: expiresInMinutes * 60 } // Convertendo minutos para segundos
        );

        res.status(200).json({ msg: 'Autenticação realizada com sucesso', token, email, password });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Erro no servidor, tente novamente mais tarde" });
    }
});

// Credentials
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.fw4dtiv.mongodb.net/?retryWrites=true&w=majority`)
    .then(() => {
        app.listen(3000);
        console.log("Connect database")
    })
    .catch((err) => console.log(err))