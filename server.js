// server.js

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pg from "pg";

dotenv.config(); // Load .env variables

// Create Express app
const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL pool
const pool = new pg.Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  ssl: { rejectUnauthorized: false },
});

// Test database connection
pool.connect()
  .then(() => console.log("Connected to Render PostgreSQL!"))
  .catch(err => console.error("Connection error", err));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";

// =======================
// Register user
// =======================
app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, email",
      [username, email, hashedPassword]
    );

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    if (err.code === "23505") { // Unique constraint error
      res.status(400).json({ error: "Email or username already exists" });
    } else {
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
});

// =======================
// Login user
// =======================
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (!result.rows.length) return res.status(400).json({ error: "Invalid credentials" });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// =======================
// Start server
// =======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
