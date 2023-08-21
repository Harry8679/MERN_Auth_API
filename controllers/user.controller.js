const asyncHandler = require('express-async-handler');
const User = require('../models/user.model');
const { generateToken } = require('../utils/index.util');
const parser = require('ua-parser-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Register : Create a account
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

// Login
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
        res.status(400);
        throw new Error('Veuillez renseigner votre email et mot de passe');
    }

    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error('Utilisateur inexistant, veuillez vous inscrire.')
    }

    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if (!passwordIsCorrect) {
        res.status(400);
        throw new Error('Email ou mot de passe est incorrect !');
    }

    // Generate Token
    const token = generateToken(user._id);

    if (user && passwordIsCorrect) {
        // Send HTTP-only cookie
        res.cookie('token', token, {
            path: '/',
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400),
            sameSite: 'none',
            secure: true
        });

        const { _id, name, email, phone, bio, photo, role, isVerified } = user;

        res.status(200).json({
            _id, name, email, phone, bio, photo, role, isVerified, token
        });
    } else {
        res.status(500);
        throw new Error('Une erreur s\'est produite, veuillez réessayer !');
    }
});

// Logout
const logoutUser = asyncHandler(async (req, res) => {
    res.cookie('token', '', {
        path: '/',
        httpOnly: true,
        expires: new Date(0),
        sameSite: 'none',
        secure: true
    });

    return res.status(200).json({ message: 'Vous avez bien été déconnecté.' })
});

// Profile
const getUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { _id, name, email, phone, bio, photo, role, isVerified } = user;

        res.status(200).json({
            _id, name, email, phone, bio, photo, role, isVerified
        });
    } else {
        res.status(500);
        throw new Error('Utilisateur inexistant');
    }
});

// Update his profile
const updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { name, email,  phone, bio, photo, role, isVerified } = user;

        user.name = req.body.name || name;
        user.email = req.body.email || email;
        user.phone = req.body.phone || phone;
        user.bio = req.body.bio || bio;
        user.photo = req.body.photo || photo;

        const updateUser = await user.save();

        res.status(200).json({
            _id: updateUser._id, 
            name: updateUser.name, 
            email: updateUser.email, 
            phone: updateUser.phone, 
            bio: updateUser.bio, 
            photo: updateUser.photo, 
            role: updateUser.role, 
            isVerified: updateUser.isVerified
        });
    }
});

// Delete a user
const deleteUser = asyncHandler(async(req, res) => {
    const user = User.findById(req.params.id);

    if (!user) {
        res.status(404);
        throw new Error('Utilisateur inexistant');
    }

    // await user.remove();
    await user.deleteOne();
    res.status(200).json({
        message: 'Cet utilisateur a bien été supprimé !'
    });
});

// Get All Users
const getUsers = asyncHandler(async(req, res) => {
    const users = await User.find().sort('-createdAt').select('-password');

    if (!users) {
        res.status(500);
        throw new Error('Une erreur s\'est produite !');
    }

    res.status(200).json(users);
});

// Login Status
const loginStatus = asyncHandler(async(req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.json(false);
    }

    // Verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    if (verified) {
        return res.json(true);
    } else {
        return res.json(false);
    }
});

// Change the Role of a user
const upgradeUser = asyncHandler(async(req, res) => {
    const { id, role } = req.body;
    
    const user = await User.findById(id);

    if (!user) {
        res.status(500);
        throw new Error('Utilisateur non existant !');
    }

    user.role = role;
    await user.save();

    res.status(200).json({ message: `Cet utilisateur à désormais le role ${role}` });
});

module.exports = { registerUser, loginUser, logoutUser, getUser, updateUser, deleteUser, getUsers, loginStatus, upgradeUser };