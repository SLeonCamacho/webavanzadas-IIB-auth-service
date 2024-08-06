const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const register = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).send('All fields are required');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const client = await pool.connect();
    const result = await client.query(
      'INSERT INTO Users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashedPassword]
    );

    client.release();
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).send('Error registering user');
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('All fields are required');
  }

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM Users WHERE email = $1', [email]);
    client.release();

    if (result.rows.length === 0) {
      return res.status(401).send('Invalid credentials');
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).send('Invalid credentials');
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({ token });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).send('Error logging in user');
  }
};

module.exports = {
  register,
  login,
};
