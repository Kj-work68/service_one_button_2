const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const userModel = require('./userModel');

const JWT_SECRET = 'your-secret-key';

const register = async (req, res) => {
  const { email, password, fname, lname, role } = req.body;
  try {
    const userId = await userModel.registerUser(email, password, fname, lname, role);
    res.status(201).json({ userId });
  } catch (error) {
    res.status(500).json({ error: 'Failed to register user' });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await userModel.findUserByEmail(email);
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ userId: user.user_id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to login' });
  }
};

const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

const logout = (req, res) => {
  // On client-side, you need to handle the token removal
  res.status(200).json({ message: 'Logged out successfully' });
};

module.exports = { register, login, authenticateJWT, logout };
