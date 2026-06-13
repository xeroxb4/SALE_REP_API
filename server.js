const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ── CONNECT TO MONGODB ──
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

const JWT_SECRET = process.env.JWT_SECRET || 'salesrep_secret_2024';

// ── SCHEMAS ──
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, enum: ['manager', 'rep'], default: 'rep' },
  email: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const ShopSchema = new mongoose.Schema({
  repId: { type: String, required: true },
  name: { type: String, required: true },
  owner: String,
  contact: String,
  location: String,
  tin: String,
  creditLimit: { type: Number, default: 0 },
  notes: String,
  routeDays: [String],
  createdAt: { type: Date, default: Date.now }
});

const OrderSchema = new mongoose.Schema({
  orderNum: String,
  repId: String,
  shopId: String,
  distributor: String,
  products: [{
    name: String,
    variant: String,
    qty: Number,
    unit: String,
    unitPrice: Number
  }],
  date: String,
  paymentType: String,
  creditWeeks: Number,
  creditDue: String,
  notes: String,
  payments: [{
    amount: Number,
    date: String,
    note: String
  }],
  createdAt: { type: Date, default: Date.now }
});

const VisitSchema = new mongoose.Schema({
  repId: String,
  shopId: String,
  date: String,
  note: String,
  createdAt: { type: Date, default: Date.now }
});

const User  = mongoose.model('User',  UserSchema);
const Shop  = mongoose.model('Shop',  ShopSchema);
const Order = mongoose.model('Order', OrderSchema);
const Visit = mongoose.model('Visit', VisitSchema);

// ── AUTH MIDDLEWARE ──
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function managerOnly(req, res, next) {
  if (req.user.role !== 'manager') return res.status(403).json({ error: 'Manager only' });
  next();
}

// ── SEED MANAGER ON FIRST RUN ──
async function seedManager() {
  const exists = await User.findOne({ role: 'manager' });
  if (!exists) {
    const hashed = await bcrypt.hash('admin123', 10);
    await User.create({ username: 'manager', password: hashed, name: 'Manager', role: 'manager' });
    console.log('Default manager created: manager / admin123');
  }
}
seedManager();

// ── AUTH ROUTES ──
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, username: user.username, name: user.name, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user._id, username: user.username, name: user.name, role: user.role, email: user.email } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login/google', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: 'No account linked to this Google email' });
    const token = jwt.sign({ id: user._id, username: user.username, name: user.name, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user._id, username: user.username, name: user.name, role: user.role, email: user.email } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── USER ROUTES ──
app.get('/api/users', auth, managerOnly, async (req, res) => {
  try {
    const users = await User.find({}, '-password');
    res.json(users);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users', auth, managerOnly, async (req, res) => {
  try {
    const { username, password, name, email } = req.body;
    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ error: 'Username already exists' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashed, name, role: 'rep', email: email?.toLowerCase() || '' });
    res.json({ id: user._id, username: user.username, name: user.name, role: user.role, email: user.email });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/:id', auth, managerOnly, async (req, res) => {
  try {
    const update = { ...req.body };
    if (update.password) update.password = await bcrypt.hash(update.password, 10);
    if (update.email) update.email = update.email.toLowerCase();
    const user = await User.findByIdAndUpdate(req.params.id, update, { new: true, select: '-password' });
    res.json(user);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', auth, managerOnly, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── SHOP ROUTES ──
app.get('/api/shops', auth, async (req, res) => {
  try {
    const query = req.user.role === 'manager' ? {} : { repId: req.user.id };
    const shops = await Shop.find(query).sort({ name: 1 });
    res.json(shops);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/shops', auth, async (req, res) => {
  try {
    const shop = await Shop.create({ ...req.body, repId: req.user.id });
    res.json(shop);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/shops/:id', auth, async (req, res) => {
  try {
    const shop = await Shop.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(shop);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/shops/:id', auth, async (req, res) => {
  try {
    await Shop.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ORDER ROUTES ──
app.get('/api/orders', auth, async (req, res) => {
  try {
    const query = req.user.role === 'manager' ? {} : { repId: req.user.id };
    const orders = await Order.find(query).sort({ createdAt: -1 });
    res.json(orders);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/orders', auth, async (req, res) => {
  try {
    // Generate order number
    const count = await Order.countDocuments();
    const orderNum = 'ORD-' + String(count + 1).padStart(4, '0');
    const order = await Order.create({ ...req.body, repId: req.user.id, orderNum });
    res.json(order);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/orders/:id', auth, async (req, res) => {
  try {
    const order = await Order.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(order);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/orders/:id', auth, async (req, res) => {
  try {
    await Order.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Add payment to order
app.post('/api/orders/:id/payments', auth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    order.payments.push(req.body);
    await order.save();
    res.json(order);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── VISIT ROUTES ──
app.get('/api/visits', auth, async (req, res) => {
  try {
    const query = req.user.role === 'manager' ? {} : { repId: req.user.id };
    const visits = await Visit.find(query).sort({ createdAt: -1 });
    res.json(visits);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/visits', auth, async (req, res) => {
  try {
    // Remove existing visit for same shop+rep+date
    await Visit.deleteOne({ repId: req.user.id, shopId: req.body.shopId, date: req.body.date });
    const visit = await Visit.create({ ...req.body, repId: req.user.id });
    res.json(visit);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── HEALTH CHECK ──
app.get('/', (req, res) => res.json({ status: 'Sales Rep API running', version: '1.0.0' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
