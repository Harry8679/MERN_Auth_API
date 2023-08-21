const express = require('express');
const { registerUser, loginUser, logoutUser, getUser } = require('../controllers/user.controller');
const { protect } = require('../middlewares/auth.middleware');
const userRouter = express.Router();

userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);
userRouter.get('/logout', logoutUser);
userRouter.get('/getUser', protect, getUser);

module.exports = userRouter;