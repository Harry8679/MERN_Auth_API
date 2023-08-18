require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const app = express();

const PORT = process.env.PORT || 5010;

app.get('/', (rea, res) => {
    res.send('Home Page');
});

mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
        console.log(`Server is running at ${PORT}`);
    })
    .catch((err) => console.log(err));