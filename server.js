// server.js

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const CryptoJS = require('crypto-js');
const { ethers } = require('ethers');
const User = require('./models/User');
const authenticateAPIKey = require('./middleware/authenticateAPIKey');

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

const app = express();
app.use(express.json());

app.post('/create-wallet', authenticateAPIKey, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required' });
        }
        const hashedPassword = bcrypt.hashSync(password, 10);
        const wallet = ethers.Wallet.createRandom();
        const encryptedPrivateKey = CryptoJS.AES.encrypt(wallet.privateKey, process.env.ENCRYPTION_SECRET).toString();
        const user = new User({ email, password: hashedPassword, walletAddress: wallet.address, encryptedPrivateKey });
        await user.save();
        res.json({ success: true, walletAddress: wallet.address });
    } catch (error) {
        console.error('Create Wallet Error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/login', authenticateAPIKey, async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ success: false, message: 'Login failed' });
        }
        res.json({ success: true, walletAddress: user.walletAddress });
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
