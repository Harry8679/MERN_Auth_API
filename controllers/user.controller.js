const asyncHandler = require('express-async-handler');
const User = require('../models/user.model');
const Token = require('../models/token.model');
const { generateToken, hashToken } = require('../utils/index.util');
const parser = require('ua-parser-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail.util');
const crypto = require('crypto');

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


const sendAutomatedEmail = asyncHandler(async(req, res) => {
    const { subject, send_to, reply_to, template, url } = req.body;

    if (!subject || !send_to || !reply_to || !template) {
        res.status(500);
        throw new Error('Un ou plusieurs paramètres sont manquants');
    }

    // Get user
    const user = await User.findOne({ email: send_to });

    if (!user) {
        res.status(404);
        throw new Error('Utilisateur non trouvé');
    }

    const sent_from = process.env.EMAIL_USER;
    const name = user.name;
    const link = `${process.env.FRONTEND_URL}${url}`;

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
        res.status(200).json({ message: 'Email envoyé !' });
    } catch(error) {
        res.status(500);
        throw new Error('L\'Email n\'a pas été envoyé, veuillez réessayer');
    }
});

const sendVerificationEmail = asyncHandler(async(req, res) => {
    const user = await User.findById(req.user._id);

    if (!user) {
        res.status(404);
        throw new Error('Utilisateur non trouvé.');
    }
    
    if (user.isVerified) {
        res.status(400);
        throw new Error('Compte déjà vérifié.')
    }

    // Delete Token if it exists in DB
    let token = await Token.findOne({ userId: user._id })

    if (token) {
        await token.deleteOne();
    }

    // Create verification Token and save
    const verificationToken = crypto.randomBytes(32).toString('hex') + user._id;
    console.log(verificationToken);
    const hashedToken = hashToken(verificationToken);
    await new Token({
        userId: user._id,
        vToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60*1000) // 1h
    }).save();

    // Construct verification URL
    const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

    //Send Email
    const subject = 'Vérifier Votre Compte - EMARH:AUTH';
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = 'noreply@emarh-auth.fr';
    const template = 'verifyEmail';
    const name = user.name;
    const link = verificationUrl;

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
        res.status(200).json({ message: 'Email de vérification envoyé !' });
    } catch(error) {
        res.status(500);
        throw new Error('L\'Email n\'a pas été envoyé, veuillez réessayer');
    }
});

const verifyUser = asyncHandler(async(req, res) => {
    const { verificationToken } = req.params;

    const hashedToken = hashToken(verificationToken);

    const userToken = await Token.findOne({
        vToken: hashedToken,
        expiresAt: {$gt: Date.now()}
    });

    if (!userToken) {
        res.status(404);
        throw new Error('Token Invalide ou Expiré');
    }

    // Find User
    const user = await User.findOne({ _id: userToken.userId });

    if (user.isVerified) {
        res.status(400);
        throw new Error('Ce Compte a déjà été vérifié.')
    }

    // Now verify user
    user.isVerified = true;
    await user.save();

    res.status(200).json({ message: 'La Vérification de Votre Compte a été effctuée avec succès !' });
});

const forgotPassword = asyncHandler(async(req, res) => {

    const { email } = req.body;

    const user = await User.findOne({ email });

    if(!user) {
        res.status(404);
        throw new Error('Cet email n\'existe pas.');
    }

    // Delete Token if it exists in DB
    let token = await Token.findOne({ userId: user._id });

    if (token) {
        await token.deleteOne();
    }

    // Create Verification Token and Save
    const resetToken = crypto.randomBytes(32).toString('hex') + user._id;
    // console.log('resetToken', resetToken);

    // Hash token and save
    const hashedToken = hashToken(resetToken);
    await new Token({
        userId: user._id,
        rToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000) // 1h
    }).save();

    // Construct Reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

    // Send Email
    const subject = 'Réinitialiser votre mot de passe - EMARH:AUTH';
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = 'noreply@emarh-auth.fr';
    const template = 'forgotPassword';
    const name = user.name;
    const link = resetUrl;

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
        res.status(200).json({ message: 'Mot de passe réinitialisé et email envoyé !' });
    } catch(error) {
        res.status(500);
        throw new Error('L\'Email n\'a pas été envoyé, veuillez réessayer');
    }
});

module.exports = { registerUser, loginUser, logoutUser, getUser, updateUser, deleteUser, getUsers, loginStatus, upgradeUser, sendAutomatedEmail, sendVerificationEmail, verifyUser, forgotPassword };