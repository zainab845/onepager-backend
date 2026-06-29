require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Could not connect to MongoDB', err));

// --- MONGOOSE MODELS ---
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true } 
});
const Admin = mongoose.model('Admin', adminSchema);

const sectionSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  image: { type: String },
  order: { type: Number, default: 0 }
});
const Section = mongoose.model('Section', sectionSchema);




// --- AUTHENTICATION ROUTE ---
app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await Admin.findOne({ email: req.body.email });
        if (!user || user.password !== req.body.password) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, name: 'Admin', email: user.email });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// --- PUBLIC ROUTE ---
app.get('/api/sections', async (req, res) => {
    try {
        const sections = await Section.find().sort({ order: 1 });
        res.json(sections); 
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// --- PROTECTED ROUTES ---
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.post('/api/sections', authenticateToken, async (req, res) => {
    try {
        const newSection = new Section(req.body);
        await newSection.save();
        res.status(201).json({ message: 'Section created' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/sections/:id', authenticateToken, async (req, res) => {
    try {
        await Section.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: 'Section updated' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.delete('/api/sections/:id', authenticateToken, async (req, res) => {
    try {
        await Section.findByIdAndDelete(req.params.id);
        res.json({ message: 'Section deleted' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// --- START SERVER ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));