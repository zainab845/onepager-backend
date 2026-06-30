require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = express();

app.use(cors({
  origin: '*',
  credentials: false,
}));
app.use(express.json());

// --- SERVERLESS-SAFE DATABASE CONNECTION ---
let isConnected = false;

const connectDB = async () => {
  if (isConnected) return;
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
    });
    isConnected = true;
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('Could not connect to MongoDB', err);
    throw err;
  }
};

// Middleware to ensure DB is connected before every request
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    res.status(500).json({ message: 'Database connection failed', error: err.message });
  }
});

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
}, { timestamps: true });
const Section = mongoose.model('Section', sectionSchema);

const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  website: { type: String },
  message: { type: String, required: true },
}, { timestamps: true });
const Contact = mongoose.model('Contact', contactSchema);

// --- AUTH ROUTES ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const user = await Admin.findOne({ email: req.body.email });
    if (!user || user.password !== req.body.password) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, name: 'Admin', email: user.email });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// --- PUBLIC ROUTES ---
app.get('/', (req, res) => {
  res.json({ message: 'Onepager API is running' });
});

app.get('/api/sections', async (req, res) => {
  try {
    const sections = await Section.find().sort({ order: 1 });
    res.json(sections);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, website, message } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ message: 'Name, email and message are required' });
    }
    const contact = await Contact.create({ name, email, website, message });
    res.status(201).json({ message: 'Message sent successfully!', contact });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- PROTECTED ROUTES ---
app.post('/api/sections', authenticateToken, async (req, res) => {
  try {
    const newSection = new Section(req.body);
    const saved = await newSection.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/sections/:id', authenticateToken, async (req, res) => {
  try {
    const updated = await Section.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    res.json(updated);
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

module.exports = app;