const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./model/User'); // Mongoose User model
const cors= require('cors');
//Registration end point 
const app = express();
app.use(express.json());
app.use(cors());

app.post('/register', async (req, res) => {
    try {
        const { username, email, password, contact, age, jobRole } = req.body;

        // Hash password before saving
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword, contact, age, jobRole });

        await newUser.save();
        res.status(201).send('User registered successfully!');
    } catch (error) {
        res.status(500).send('Error: ' + error.message);
    }
});

//Login Endpoint with JWT

const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Compare entered password with stored hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).send('Invalid credentials');
        }

        // Generate JWT Token
        const token = jwt.sign(
            { id: user._id, email: user.email }, // Payload
            process.env.JWT_SECRET,             // Secret key
            { expiresIn: process.env.JWT_EXPIRES_IN } // Options
        );

        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        res.status(500).send('Error: ' + error.message);
    }
});


//Middleware to Protect Routes

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1]; // Extract token
    if (!token) {
        return res.status(401).send('Access denied. No token provided.');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token
        req.user = decoded; // Attach user info to request
        next();
    } catch (error) {
        res.status(400).send('Invalid token');
    }
};

// Example of a protected route
app.get('/protected', authMiddleware, (req, res) => {
    res.status(200).send(`Welcome, user with ID: ${req.user.id}`);
});



if(mongoose.connect('mongodb+srv://JkRDwaraka0608:JkRDwaraka0608@cluster0.z0bxu.mongodb.net/logregpage?retryWrites=true&w=majority&appName=Cluster0'))
{
    console.log('Database is connected');
}
   

app.listen(4000,()=>
{
    console.log('Server is running')
})