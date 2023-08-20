const asyncHandler = require('express-async-handler');
const User = require('../models/user.model');
const { generateToken } = require('../utils/index.util');
const parser = require('ua-parser-js');

const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
        res.status(400)
        throw new Error('Veuillez renseigner tous les champs obligatoires');
    }

    if (password.length < 6) {
        res.status(400)
        throw new Error('Le mot de passe doit avoir au moins 6 caractères');
    }

    // Check if user exists
    const userExists = await User.findOne({ email });

    if (userExists) {
        res.status(400)
        throw new Error('Cet email exist déjà !');
    }

    // Get UserAgent
    const ua = parser(req.headers['user-agent']);
    const userAgent = [ua.ua];

    // Create new User
    const user = await User.create({ name, email, password, userAgent });

    // Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie('token', token, {
        path: '/',
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 864000), // 1 day
        sameSite: 'none',
        secure: true
    });

    if (user) {
        const { _id, name, email, phone, bio, photo, role, isVerified } = user;

        res.status(201).json({
            _id, name, email, phone, bio, photo, role, isVerified, token
        });
    } else {
        res.status(400)
        throw new Error('Données utilisateur invalides.');
    }
});

const loginUser = asyncHandler(async (req, res) => {
    res.send('Login');
});

module.exports = { registerUser, loginUser };