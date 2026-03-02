import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pkg from "pg";
const { Pool } = pkg;

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// Register user
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  const password_hash = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      "INSERT INTO users (name,email,password_hash) VALUES ($1,$2,$3) RETURNING id,email",
      [name, email, password_hash]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(400).json({ error: "Email already exists" });
  }
});

// Login user
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (!result.rows.length) return res.status(400).json({ error: "Invalid credentials" });

  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, token });
});

app.listen(3000, () => console.log("Backend running on port 3000"));