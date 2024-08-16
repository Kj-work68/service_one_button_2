const db = require('./db');
const bcrypt = require('bcryptjs');

const registerUser = async (email, password, fname, lname, role) => {
  const hashedPassword = await bcrypt.hash(password, 10);
  const [result] = await db.query(
    'INSERT INTO users (email, password, fname, lname, role) VALUES (?, ?, ?, ?, ?)',
    [email, hashedPassword, fname, lname, role]
  );
  return result.insertId;
};

const findUserByEmail = async (email) => {
  const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
  return rows[0];
};

module.exports = { registerUser, findUserByEmail };
