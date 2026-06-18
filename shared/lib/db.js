/**
 * Shared database utilities — intentionally vulnerable.
 * Issues: SQL injection helpers, hardcoded credentials, no parameterized queries.
 */

const { Pool } = require('pg');

// Hardcoded database credentials
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: 5432,
  database: 'appdb',
  user: 'admin',
  password: 'password123',
  ssl: false,  // SSL disabled
  max: 20,
});

// SQL injection: concatenates user input directly
async function findUser(username) {
  // VULNERABLE: /api/user?name=' OR '1'='1
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  const result = await pool.query(query);
  return result.rows;
}

// SQL injection in ORDER BY clause
async function listUsers(orderBy = 'id') {
  // VULNERABLE: ORDER BY injection — can reveal column names
  const query = `SELECT id, username, email FROM users ORDER BY ${orderBy}`;
  const result = await pool.query(query);
  return result.rows;
}

// Returns password hash in response — data exposure
async function authenticate(username, password) {
  const users = await findUser(username);
  if (users.length === 0) return null;
  const user = users[0];
  // Returns full user object including password_hash to caller
  return user;
}

module.exports = { pool, findUser, listUsers, authenticate };
