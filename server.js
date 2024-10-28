const express = require('express');
const app = express();
const cors = require('cors');
const mongoose = require('mongoose');
const User = require('./models/user.model');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();

app.use(cors());
app.use(express.json());

mongoose.set("strictQuery", true);
const db = process.env.MONGODB_URI;
const secretkey = process.env.SECRET_KEY;

// Log the MongoDB URI to ensure it's being loaded correctly
console.log('MongoDB URI:', db);

const connectDB = async () => {
    try {
        await mongoose.connect(db, { useNewUrlParser: true, useUnifiedTopology: true });
        console.log('MongoDB connected...');
    } catch (err) {
        console.error('Error connecting to MongoDB:', err.message);
        process.exit(1);
    }
};

connectDB();

app.post('/api/register', async (req, res) => {
    try {
        const newPassword = await bcrypt.hash(req.body.password, 10);
        await User.create({
            email: req.body.email,
            password: newPassword,
        });
        res.json({ status: 'ok' });
    } catch (err) {
        res.json({ status: 'error', error: 'Duplicate email' });
    }
});


app.post('/api/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
        return res.json({ status: 'error', error: 'Invalid login' });
    }

    const isPasswordValid = await bcrypt.compare(req.body.password, user.password);

    if (isPasswordValid) {
        const token = jwt.sign({ email: user.email, id: user.id }, 'secret123', { expiresIn: '1d' });
        // const token = jwt.sign({ email: user.email, id: user._id }, secretkey, { expiresIn: '1h' }); // Add user id to the token payload
        return res.json({ status: 'ok', token, user: { email: user.email, id: user._id } }); // Return token and user info
    } else {
        return res.json({ status: 'error', error: 'Invalid password' });
    }
});

app.post('/api/verify-token', (req, res) => {
    const token = req.body.token;

    if (!token) {
        return res.json({ status: 'error', error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, secretkey); // Verify the token with the same secret
        return res.json({ status: 'ok', user: decoded }); // Send back decoded user info
    } catch (error) {
        return res.json({ status: 'error', error: 'Invalid token' });
    }
});


app.get('/api/quote', async (req, res) => {
    const token = req.headers['x-access-token'];

    try {
        const decoded = jwt.verify(token, secretkey);
        const email = decoded.email;
        const user = await User.findOne({ email: email });
        return res.json({ status: 'ok', quote: user.quote });
    } catch (error) {
        res.json({ status: 'error', error: 'invalid token' });
    }
});

app.post('/api/quote', async (req, res) => {
    const token = req.headers['x-access-token'];

    try {
        const decoded = jwt.verify(token, secretkey);
        const email = decoded.email;
        await User.updateOne({ email: email }, { $set: { quote: req.body.quote } });
        return res.json({ status: 'ok' });
    } catch (error) {
        res.json({ status: 'error', error: 'invalid token' });
    }
});

// Function to insert dummy user data
const insertDummyUser = async () => {
    const dummyUser = {
        email: "minku@aeroqube.com",
        password: "Aero@123",
        quote: "hey"
    };

    try {
        const newPassword = await bcrypt.hash(dummyUser.password, 10);
        const newUser = new User({
            email: dummyUser.email,
            password: newPassword,
            quote: dummyUser.quote
        });
        await newUser.save();
        console.log('Dummy user inserted:', newUser);
    } catch (error) {
        console.error('Error inserting dummy user:', error);
    }
};

// Insert the dummy user when the server starts
// insertDummyUser();

app.listen(4000, () => {
    //console.log('Server started on 4000');
});
