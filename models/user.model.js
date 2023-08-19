const mongoose = require('mongoose');

const userSchema = mongoose.Schema(
    {
        name: {
            type: String,
            required: [true, 'Veuillez entrer votre nom']
        },
        email: {
            type: String,
            required: [true, 'Veuillez entrer votre email'],
            unique: true,
            trim: true,
            match: [
                /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
            ]
        },
        password: {
            type: String,
            required: [true, 'Veuillez entrer votre mot de passe']
        },
        photo: {
            type: String,
            required: [true, 'Veuillez télécharger une photo'],
            default: 'https://github.com/zinotrust/auth-app-styles/blob/master/assets/avatarr.png?raw=true'
        },
        phone: {
            type: String,
            default: '+241'
        },
        bio: {
            type: String,
            default: 'Votre biographie'
        },
        role: {
            type: String,
            default: 'Abonné(e)'
        },
        isVerified: {
            type: Boolean,
            default: false
        },
        userAgent: {
            type: Array,
            required: true, 
            default: []
        }
    },
    {
        timestamps: true,
        minimize: false,
    }
);

const User = mongoose.model('User', userSchema);

module.exports = User;