// ------------------- Load Environment Variables -------------------
require("dotenv").config();

// ------------------- Imports -------------------
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

// ------------------- Middleware -------------------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public"))); // Serve static files

// ------------------- MySQL Connection (Async Pool) -------------------
let pool;

async function initDB() {
  try {
    const dbConfig = {
      host: process.env.DB_HOST || "localhost",
      port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
      user: process.env.DB_USER || "cookbook_user",
      password: process.env.DB_PASS || "cookbook_pass",
      database: process.env.DB_NAME || "cookbook_db",
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    };

    // Optional SSL (Render + Cloud DBs like PlanetScale, TiDB, etc.)
    if (process.env.DB_SSL_CA) {
      dbConfig.ssl = { ca: fs.readFileSync(process.env.DB_SSL_CA) };
    }

    pool = await mysql.createPool(dbConfig);
    console.log("✅ Database connected successfully!");

    // Ensure the "users" table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fullname VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log("🗂 Table check complete (users)");
  } catch (err) {
    console.error("❌ Failed to initialize database:", err);
    process.exit(1);
  }
}

// ------------------- ROUTES -------------------

// ✅ SIGNUP Route
app.post("/signup", async (req, res) => {
  const { fullname, email, password } = req.body;

  if (!fullname || !email || !password)
    return res.status(400).json({ message: "All fields are required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)",
      [fullname, email, hashedPassword]
    );

    res.json({ message: "User registered successfully!" });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ message: "Email already exists" });
    }
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ LOGIN Route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "All fields are required" });

  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0)
      return res.status(401).json({ message: "Invalid email or password" });

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch)
      return res.status(401).json({ message: "Invalid email or password" });

    res.json({ message: `Welcome, ${user.fullname}!` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ------------------- PAGE ROUTES -------------------
app.get("/home", (req, res) => res.sendFile(path.join(__dirname, "public", "home.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/index", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ------------------- START SERVER -------------------
initDB().then(() => {
  app.listen(process.env.PORT || 3000, "0.0.0.0", () => {
    console.log(`🚀 Server running on port ${process.env.PORT || 3000}`);
  });
});




