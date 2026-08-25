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
        minVersion: "TLSv1.2",
        rejectUnauthorized: true // Explicitly required by TiDB Cloud secure public endpoints
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
        let tasks = [];
        let userName = "Student";

        if (req.user && req.user.id) {
            userName = req.user.name || "Student";
            const [rows] = await db.execute(
                "SELECT * FROM tasks WHERE user_id = ? ORDER BY id DESC",
                [req.user.id]
            );
            tasks = rows;
        }

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
   ADD TASK ROUTES
========================= */

// 1. Handles the form submission data reliably
app.post("/add-task", async (req, res) => {
    try {
        const { title, description } = req.body;
        
        // Use active authenticated user ID, or fallback to 1 for standalone debugging
        const userId = (req.user && req.user.id) ? req.user.id : 1; 

        if (!title) {
            return res.status(400).send("Task title is required.");
        }

        await db.execute(
            "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
            [userId, title, description || ""]
        );

        res.redirect("/");
    } catch (error) {
        console.error("Failed to add task:", error);
        
        // Exposes exact schema failures (like missing tables) directly to the screen
        res.status(500).json({ 
            status: "Database Task Insertion Failed",
            errorMessage: error.message, 
            errorCode: error.code,
            sqlState: error.sqlState
        });
    }
});

// 2. Fixes the "Cannot GET /add-task" error by safely bouncing users back to dashboard
app.get("/add-task", (req, res) => {
    res.redirect("/");
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
   LOGIN (FIXED ARRAY ACCESS)
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

        // FIXED: Extract the first record out of the rows array returned by mysql2/promise
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
        console.error("Login route crashed:", error);
        res.status(500).json({
            message: "Login processing crash",
            error: error.message
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
    console.log(`Server running at http://localhost:${PORT}`);
});
