const mongoose = require('mongoose');

const tokenSchema = mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            required: true,
            ref: 'user'
        },
        vToken: {
            type: String,
            default: ''
        },
        rToken: {
            type: String,
            default: ''
        },
        lToken: {
            type: String,
        },
        createdAt: {
            type: Date,
            required: true
        },
        expiresAt: {
            type: Date,
            required: true
        }
    }
);

// Encrypt password before saving to DB
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        return next();
    }

    // Hash Password
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(this.password, salt);
    this.password = hashPassword;
    next();
})

const Token = mongoose.model('Token', tokenSchema);

module.exports = Token;