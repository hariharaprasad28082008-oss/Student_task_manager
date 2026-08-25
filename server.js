const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
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
   AUTHENTICATION MIDDLEWARE
========================= */

function authenticate(req, res, next) {
    let token = req.cookies.token;

    if (!token && req.headers.authorization) {
        const parts = req.headers.authorization.split(" ");
        if (parts[0] === "Bearer") token = parts[1];
    }

    if (!token) {
        return res.redirect("/login");
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.clearCookie("token");
        return res.redirect("/login");
    }
}

/* =========================
   VISUAL PAGE ROUTING (EJS VIEWS)
========================= */

// HOME (DASHBOARD)
app.get("/", authenticate, async (req, res) => {
    try {
        const userName = req.user.name || "Student";
        const [rows] = await db.execute(
            "SELECT * FROM tasks WHERE user_id = ? ORDER BY id DESC",
            [req.user.id]
        );

        res.render("index", {
            tasks: rows || [],
            user: { name: userName }
        });
    } catch (error) {
        console.error("Dashboard compilation failed:", error);
        res.status(500).send("Internal Server Error: Failed to render dashboard.");
    }
});

// LOGIN PAGE VIEW
app.get("/login", (req, res) => {
    res.render("login");
});

// SIGN UP PAGE VIEW
app.get("/signup", (req, res) => {
    res.render("signup");
});

// ADD TASK PAGE VIEW
app.get("/add-task", authenticate, (req, res) => {
    res.render("add-task");
});

// EDIT TASK PAGE VIEW
app.get("/edit-task/:id", authenticate, async (req, res) => {
    try {
        const taskId = req.params.id;
        const [results] = await db.execute(
            "SELECT * FROM tasks WHERE id = ? AND user_id = ?", 
            [taskId, req.user.id]
        );

        if (results.length === 0) {
            return res.status(404).send("Task not found.");
        }

        res.render("edit-task", { task: results[0] });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error fetching task view.");
    }
});

/* =========================
   AUTHENTICATION ACTION ENDPOINTS
========================= */

// SIGN UP METHOD
app.post("/signup", async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (!name || !email || !password) {
            return res.status(400).send("All fields are required");
        }

        const [existingUsers] = await db.execute(
            "SELECT id FROM users WHERE email = ?",
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).send("Email already registered");
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await db.execute(
            `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`,
            [name, email, hashedPassword]
        );

        res.redirect("/login");
    } catch (error) {
        console.error(error);
        res.status(500).send(`Registration failed. Error Details: ${error.message}`);
    }
});

// LOGIN METHOD
app.post("/login", async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (!email || !password) {
            return res.status(400).send("Email and password are required");
        }

        const [users] = await db.execute(
            "SELECT * FROM users WHERE email = ?",
            [email]
        );

        if (users.length === 0) {
            return res.status(401).send("Invalid email or password");
        }

        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).send("Invalid email or password");
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, name: user.name },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.redirect("/");
    } catch (error) {
        console.error(error);
        res.status(500).send(`Login failed. Error Details: ${error.message}`);
    }
});

// LOGOUT POST ACTION
app.post("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/login");
});

/* =========================
   TASK HANDLING PROCESS ACTIONS
========================= */

// ADD TASK PROCESS ACTION
app.post("/add-task", authenticate, async (req, res) => {
    try {
        const { title, description, due_date, priority } = req.body;

        if (!title || title.trim() === "") {
            return res.status(400).send("Task title is required.");
        }

        await db.execute(
            `INSERT INTO tasks (user_id, title, description, due_date, priority, status)
             VALUES (?, ?, ?, ?, ?, 'Pending')`,
            [req.user.id, title.trim(), description || null, due_date || null, priority || "Medium"]
        );

        res.redirect("/");
    } catch (error) {
        console.error(error);
        res.status(500).send("Failed to add task.");
    }
});

// TOGGLE TASK STATUS PROCESS ACTION
app.post("/toggle-task/:id", authenticate, async (req, res) => {
    try {
        const taskId = req.params.id;

        const [tasks] = await db.execute(
            "SELECT status FROM tasks WHERE id = ? AND user_id = ?",
            [taskId, req.user.id]
        );

        if (tasks.length === 0) {
            return res.status(404).send("Task not found.");
        }

        const currentStatus = tasks[0].status;
        const newStatus = currentStatus === "Completed" ? "Pending" : "Completed";

        await db.execute(
            "UPDATE tasks SET status = ? WHERE id = ? AND user_id = ?",
            [newStatus, taskId, req.user.id]
        );

        res.redirect("/");
    } catch (error) {
        console.error(error);
        res.status(500).send("Failed to toggle task status.");
    }
});

// EDIT TASK POST PROCESS ACTION
app.post("/edit-task/:id", authenticate, async (req, res) => {
    try {
        const taskId = req.params.id;
        const { title, description, due_date, priority, status } = req.body;

        await db.execute(
            `UPDATE tasks 
             SET title = ?, description = ?, due_date = ?, priority = ?, status = ? 
             WHERE id = ? AND user_id = ?`,
            [title.trim(), description || null, due_date || null, priority, status, taskId, req.user.id]
        );

        res.redirect("/");
    } catch (error) {
        console.error(error);
        res.status(500).send("Failed to update task.");
    }
});

// DELETE TASK PROCESS ACTION
app.post("/delete-task/:id", authenticate, async (req, res) => {
    try {
        const taskId = req.params.id;

        await db.execute(
            "DELETE FROM tasks WHERE id = ? AND user_id = ?",
            [taskId, req.user.id]
        );

        res.redirect("/");
    } catch (error) {
        console.error(error);
        res.status(500).send("Failed to delete task.");
    }
});

/* =========================
   TEST DATABASE ENDPOINT
========================= */

app.get("/test-db", async (req, res) => {
    try {
        const [result] = await db.query("SELECT 1 AS test");
        res.json({ message: "Database connected successfully!", result: result });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Database connection failed", error: error.message });
    }
});

/* =========================
   START SERVER
========================= */

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 Server running smoothly on port ${PORT}`);
});
