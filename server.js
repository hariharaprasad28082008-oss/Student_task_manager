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
app.set("view engine", "ejs");

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT) || 3306,
    ssl: {
        minVersion: "TLSv1.2",
        rejectUnauthorized: true
    }
});

/* =========================
   VIEW TEMPLATE RENDERING ROUTES
========================= */

app.get("/", async (req, res) => {
    try {
        let tasks = [];
        let userName = "Student";

        if (req.user && req.user.id) {
            userName = req.user.name || "Student";
            const [rows] = await db.execute("SELECT * FROM tasks WHERE user_id = ? ORDER BY id DESC", [req.user.id]);
            tasks = rows;
        } else {
            const [rows] = await db.execute("SELECT * FROM tasks WHERE user_id = 1 ORDER BY id DESC");
            tasks = rows;
        }

        res.render("index", { tasks: tasks, user: { name: userName } });
    } catch (error) {
        console.error("Dashboard compilation failed:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/login", (req, res) => {
    res.render("login"); 
});

// FIXED: Now accurately renders your signup.ejs file from your file structure tree layout
const renderRegisterPage = (req, res) => { res.render("signup"); }; 
app.get("/register", renderRegisterPage);
app.get("/signup", renderRegisterPage);
app.get("/sign-up", renderRegisterPage);

app.get("/add-task", (req, res) => {
    try {
        let userName = (req.user && req.user.name) ? req.user.name : "Student";
        res.render("add-task", { user: { name: userName } });
    } catch (error) {
        res.status(500).send("Error loading add task page.");
    }
});

app.post("/add-task", async (req, res) => {
    try {
        const { title, description } = req.body;
        const userId = (req.user && req.user.id) ? req.user.id : 1; 

        if (!title) return res.status(400).send("Task title is required.");

        await db.execute("INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)", [userId, title, description || ""]);
        res.redirect("/");
    } catch (error) {
        res.status(500).json({ status: "Database Task Insertion Failed", errorMessage: error.message });
    }
});

app.get("/edit-task/:id", async (req, res) => {
    try {
        const taskId = req.params.id;
        const userId = (req.user && req.user.id) ? req.user.id : 1;
        const [rows] = await db.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?", [taskId, userId]);

        if (rows.length === 0) return res.status(404).send("Task not found.");

        let userName = (req.user && req.user.name) ? req.user.name : "Student";
        res.render("edit-task", { task: rows, user: { name: userName } });
    } catch (error) {
        res.status(500).send("Error loading edit page.");
    }
});

app.post("/edit-task/:id", async (req, res) => {
    try {
        const taskId = req.params.id;
        const { title, description } = req.body;
        const userId = (req.user && req.user.id) ? req.user.id : 1;

        if (!title) return res.status(400).send("Task title is required.");

        await db.execute("UPDATE tasks SET title = ?, description = ? WHERE id = ? AND user_id = ?", [title, description || "", taskId, userId]);
        res.redirect("/");
    } catch (error) {
        res.status(500).json({ status: "Database Task Update Failed", errorMessage: error.message });
    }
});

app.post("/delete-task/:id", async (req, res) => {
    try {
        const taskId = req.params.id;
        const userId = (req.user && req.user.id) ? req.user.id : 1; 
        await db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", [taskId, userId]);
        res.redirect("/");
    } catch (error) {
        res.status(500).json({ status: "Database Deletion Failed", errorMessage: error.message });
    }
});

app.post("/logout", (req, res) => { res.redirect("/login"); });
app.get("/logout", (req, res) => { res.redirect("/login"); });

app.post("/login", async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        const [users] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
        if (users.length === 0) {
            return res.status(401).send("Invalid email or password. <a href='/login'>Try again</a>");
        }

        const user = users[0]; 
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).send("Invalid email or password. <a href='/login'>Try again</a>");
        }

        res.redirect("/");
    } catch (error) {
        console.error("Browser form login crash:", error);
        res.status(500).send("Login failure endpoint error: " + error.message);
    }
});

/* =========================
   STANDARD BROWSER SIGNUP FORM HANDLER
========================= */
const handleFormRegister = async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (!name || !email || !password) {
            return res.status(400).send("All fields are required. Please go back and fill out the form.");
        }

        const [existingUsers] = await db.execute("SELECT id FROM users WHERE email = ?", [email]);
        if (existingUsers.length > 0) {
            return res.status(400).send("Email already registered. Please go back and log in.");
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword]);
        
        res.redirect("/login");
    } catch (error) {
        console.error("Signup failed:", error);
        res.status(500).send("Registration error: " + error.message);
    }
};

app.post("/register", handleFormRegister);
app.post("/signup", handleFormRegister);
app.post("/sign-up", handleFormRegister);

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log("Server is running successfully on port " + PORT);
});
