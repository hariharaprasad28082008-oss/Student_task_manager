const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Set up template view engine so your app can use the EJS layouts
app.set("view engine", "ejs");

/* =========================
   DATABASE CONNECTION
========================= */

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT) || 3306,
    ssl: {
        minVersion: "TLSv1.2"
    }
});

/* =========================
   TEST DATABASE
========================= */

app.get("/test-db", async (req, res) => {
    try {
        const [result] = await db.query("SELECT 1 AS test");
        res.json({
            message: "Database connected successfully!",
            result: result
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Database connection failed",
            error: error.message
        });
    }
});


/* =========================
   HOME (DASHBOARD)
========================= */

app.get("/", async (req, res) => {
    try {
        // Fallback variables prevent EJS from crashing if no user is signed in yet
        let tasks = [];
        let userName = "Student";

        // Try to fetch tasks if an authenticated user session is detected
        if (req.user && req.user.id) {
            userName = req.user.name || "Student";
            const [rows] = await db.execute(
                "SELECT * FROM tasks WHERE user_id = ? ORDER BY id DESC",
                [req.user.id]
            );
            tasks = rows;
        }

        // Render your index.ejs layout template safely with standard parameters
        res.render("index", {
            tasks: tasks,
            user: {
                name: userName
            }
        });
    } catch (error) {
        console.error("Dashboard compilation failed:", error);
        res.status(500).send("Internal Server Error: Failed to render dashboard.");
    }
});


/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "All fields are required"
            });
        }

        const [existingUsers] = await db.execute(
            "SELECT id FROM users WHERE email = ?",
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({
                message: "Email already registered"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await db.execute(
            `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`,
            [name, email, hashedPassword]
        );

        res.json({
            message: "Registration successful"
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Registration failed"
        });
    }
});


/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        const [users] = await db.execute(
            "SELECT * FROM users WHERE email = ?",
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, name: user.name },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            message: "Login successful",
            token: token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Login failed"
        });
    }
});


/* =========================
   AUTHENTICATION MIDDLEWARE
========================= */

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            message: "Authentication required"
        });
    }

    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
        return res.status(401).json({
            message: "Invalid token"
        });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
}


/* =========================
   GET USER
========================= */

app.get("/api/user", authenticate, async (req, res) => {
    try {
        const [users] = await db.execute(
            `SELECT id, name, email FROM users WHERE id = ?`,
            [req.user.id]
        );

        if (users.length === 0) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        res.json(users[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Failed to get user"
        });
    }
});


/* =========================
   ADD TRANSACTION
========================= */

app.post("/api/transactions", authenticate, async (req, res) => {
    try {
        const { type, category, description, amount, transaction_date } = req.body;

        if (!type || !category || !transaction_date || !Number.isFinite(Number(amount)) || Number(amount) <= 0) {
            return res.status(400).json({
                message: "Please fill all required fields"
            });
        }

        if (type !== "income" && type !== "expense") {
            return res.status(400).json({
                message: "Invalid transaction type"
            });
        }

        await db.execute(
            `INSERT INTO transactions (user_id, type, category, description, amount, transaction_date)
            VALUES (?, ?, ?, ?, ?, ?)`,
            [req.user.id, type, category, description || "", amount, transaction_date]
        );

        res.json({
            message: "Transaction added successfully"
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Failed to add transaction"
        });
    }
});


/* =========================
   GET TRANSACTIONS
========================= */

app.get("/api/transactions", authenticate, async (req, res) => {
    try {
        const [transactions] = await db.execute(
            `SELECT id, type, category, description, amount, transaction_date 
             FROM transactions 
             WHERE user_id = ? 
             ORDER BY transaction_date DESC`,
            [req.user.id]
        );

        res.json(transactions);
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Failed to fetch transactions"
        });
    }
});


/* =========================
   START SERVER
========================= */

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 Server running smoothly on port ${PORT}`);
});
