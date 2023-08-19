require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 5010;

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(
    cors({
        origin: ['http://localhost:3000', 'https://authz-app.vercel.app'],
        credentials: true
    })
)

app.get('/', (req, res) => {
    res.send('Home Page');
});


app.listen(PORT, console.log(`Server is running on the port ${PORT}`));
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
        console.log(`Server is running at ${PORT}`);
    })
    .catch((err) => console.log(err));