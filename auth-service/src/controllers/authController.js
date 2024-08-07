const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const winston = require('winston');

// Configuración de Winston para logs
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'logs/auth.log', level: 'info' }),
    new winston.transports.Console({ format: winston.format.simple() }),
  ],
});

// Función para registrar eventos de log
const logEvent = (user, ip) => {
  logger.info({
    timestamp: new Date().toISOString(),
    ip: ip,
    user_id: user.id,
    name: user.name,
    email: user.email,
  });
};

// Registro
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

// Login
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
      return res.status(401).send('Invalid credentials: user not found');
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).send('Invalid credentials: wrong password');
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    logEvent(user, req.ip);  // Llamada para registrar el log de inicio de sesión
    res.json({ token });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).send('Error logging in user');
  }
};

// Obtener usuario por email
const getUserByEmail = async (req, res) => {
  const { email } = req.params;

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT email FROM Users WHERE email = $1', [email]);
    client.release();

    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).send('Error fetching user');
  }
};

// Obtener nombre de usuario por email
const getUserNameByEmail = async (req, res) => {
  const { email } = req.params;

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT name FROM Users WHERE email = $1', [email]);
    client.release();

    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).send('Error fetching user');
  }
};

// Obtener ID de usuario por email
const getUserIDByEmail = async (req, res) => {
  const { email } = req.params;

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT id FROM Users WHERE email = $1', [email]);
    client.release();

    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).send('Error fetching user');
  }
};

// Validar existencia de un usuario por id
const validateUser = async (req, res) => {
  const { id } = req.params;

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM Users WHERE id = $1', [id]);
    client.release();

    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    res.status(200).send('User exists');
  } catch (error) {
    console.error('Error validating user:', error);
    res.status(500).send('Error validating user');
  }
};

// Añadir esto en el archivo authController.js
const updatePassword = async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).send('All fields are required');
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const client = await pool.connect();
    const result = await client.query(
      'UPDATE Users SET password = $1 WHERE email = $2 RETURNING id, email',
      [hashedPassword, email]
    );
    client.release();

    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).send('Error updating password');
  }
};

module.exports = {
  register,
  login,
  getUserByEmail,
  getUserNameByEmail,
  getUserIDByEmail,
  validateUser,
  updatePassword,
};
