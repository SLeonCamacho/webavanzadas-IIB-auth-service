const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

const createTables = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS Users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(100) UNIQUE,
        password VARCHAR(100)
      );
    `);
    console.log('Tables created successfully');
  } catch (error) {
    console.error('Error creating tables:', error);
  } finally {
    client.release();
  }
};

const insertDefaultData = async () => {
  const client = await pool.connect();
  try {
    const password1 = await bcrypt.hash('password1', 10);
    const password2 = await bcrypt.hash('password2', 10);
    await client.query(`
      INSERT INTO Users (name, email, password)
      VALUES 
        ('Santiago', 'santiago.leon@epn.edu.ec', '${password1}'),
        ('Bobby', 'bobby@example.com', '${password2}')
      ON CONFLICT (email) DO NOTHING;
    `);
    console.log('Data inserted successfully');
  } catch (error) {
    console.error('Error inserting data:', error);
  } finally {
    client.release();
  }
};

module.exports = {
  pool,
  createTables,
  insertDefaultData,
};
