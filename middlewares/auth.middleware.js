const asyncHandler = require('express-async-handler');
const User = require('../models/user.model');
const jwt = require('jsonwebtoken');

const protect = asyncHandler(async (req, res, next) => {
    try {
        const token = req.cookies.token;

        if (!token) {
            res.status(401);
            throw new Error('Vous n\'êtes pas autorisé, veuillez vous connecter');
        }

        // Verify Token
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        // Get user id from token
        const user = await User.findById(verified.id).select('-password');

        if (!user) {
            res.status(404);
            throw new Error('Utilisateur inexistant');
        }

        if (user.role === 'suspended') {
            res.status(400);
            throw new Error('Compte suspendu, veuillez contacter le support');
        }

        req.user = user;
        next();
    } catch(error) {
        res.status(401);
        throw new Error('Vous n\'êtes pas autorisé, veuillez vous connecter');
    }
});

module.exports = { protect };