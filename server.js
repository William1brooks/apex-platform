import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pkg from "pg";

dotenv.config();
const { Pool } = pkg;

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
  ssl: { rejectUnauthorized: false } // required for some hosts like Render or Neon
});

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET;

// ----------------- User Endpoints -----------------

// Register
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email",
      [name, email, hashedPassword]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    if (err.code === "23505") { // unique constraint violation
      res.status(400).json({ error: "Email already exists" });
    } else {
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (!result.rows.length) return res.status(400).json({ error: "Invalid credentials" });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ----------------- Accounts Endpoints -----------------

app.get("/api/accounts", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM accounts");
    res.json({ accounts: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Accounts summary for dashboard charts
app.get("/api/accounts-summary", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT account_type, SUM(balance) AS total_balance FROM accounts GROUP BY account_type"
    );
    res.json({ summary: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ----------------- Trades Endpoints -----------------

app.get("/api/trades", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM trades");
    res.json({ trades: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Trades summary for dashboard charts
app.get("/api/trades-summary", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT trade_type, COUNT(*) AS total_trades, SUM(amount) AS total_amount FROM trades GROUP BY trade_type"
    );
    res.json({ summary: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ----------------- Transactions Endpoints -----------------

app.get("/api/transactions", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM transactions");
    res.json({ transactions: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ----------------- Test Endpoint -----------------

app.get("/api/test", (req, res) => {
  res.json({ message: "API is working" });
});

// ----------------- Start Server -----------------

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
