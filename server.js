process.on("uncaughtException", (err) => {
    console.error("❌ CRITICAL BOOT CRASH DETECTED:", err.message);
});

const express = require("express");
const mysql = require("mysql2"); 
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
// Added cookie-parser package to securely read active user login sessions
const cookieParser = require("cookie-parser"); 
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // Enable cookie reading
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
}).promise();

/* =========================
   SECURE AUTH MIDDLEWARE (FOR COOKIES)
========================= */
function checkUserSession(req, res, next) {
    const token = req.cookies.auth_token;
    
    if (!token) {
        return res.redirect("/login");
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || "fallback_secret_key");
        req.user = decoded; // Attaches the unique user id to the request
        next();
    } catch (error) {
        res.clearCookie("auth_token");
        return res.redirect("/login");
    }
}

/* =========================
   VIEW TEMPLATE RENDERING ROUTES
========================= */

app.get("/", (req, res) => {
    if (req.cookies.auth_token) return res.redirect("/dashboard");
    res.render("login");
});

app.get("/login", (req, res) => {
    if (req.cookies.auth_token) return res.redirect("/dashboard");
    res.render("login"); 
});

app.get("/signup", (req, res) => { res.render("signup"); });
app.get("/register", (req, res) => { res.render("signup"); });

// FIXED: Added checkUserSession to ensure users can ONLY look at their own database records
app.get("/dashboard", checkUserSession, async (req, res) => {
    try {
        // Fetches tasks that exclusively belong to the active logged-in user id!
        const [rows] = await db.execute(
            "SELECT * FROM tasks WHERE user_id = ? ORDER BY id DESC", 
            [req.user.id]
        );
        
        res.render("index", { tasks: rows, user: { name: req.user.name } });
    } catch (error) {
        console.error("Dashboard compilation failed:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/add-task", checkUserSession, (req, res) => {
    res.render("add-task", { user: { name: req.user.name } });
});

// FIXED: Tasks are now forcefully tied directly to the unique authenticated account
app.post("/add-task", checkUserSession, async (req, res) => {
    try {
        const { title, description } = req.body;

        if (!title) return res.status(400).send("Task title is required.");

        await db.execute(
            "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)", 
            [req.user.id, title, description || ""]
        );
        res.redirect("/dashboard");
    } catch (error) {
        res.status(500).send("Database Insertion Failed");
    }
});

app.get("/edit-task/:id", checkUserSession, async (req, res) => {
    try {
        const [rows] = await db.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?", [req.params.id, req.user.id]);
        if (rows.length === 0) return res.status(404).send("Task not found.");
        res.render("edit-task", { task: rows[0], user: { name: req.user.name } });
    } catch (error) {
        res.status(500).send("Error loading edit page.");
    }
});

app.post("/edit-task/:id", checkUserSession, async (req, res) => {
    try {
        const { title, description } = req.body;
        await db.execute(
            "UPDATE tasks SET title = ?, description = ? WHERE id = ? AND user_id = ?", 
            [title, description || "", req.params.id, req.user.id]
        );
        res.redirect("/dashboard");
    } catch (error) {
        res.status(500).send("Update Failed");
    }
});

app.post("/delete-task/:id", checkUserSession, async (req, res) => {
    try {
        await db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", [req.params.id, req.user.id]);
        res.redirect("/dashboard");
    } catch (error) {
        res.status(500).send("Deletion Failed");
    }
});

// FIXED LOGOUT: Securely wipes the auth session from the client browser
app.get("/logout", (req, res) => {
    res.clearCookie("auth_token");
    res.redirect("/login");
});
app.post("/logout", (req, res) => {
    res.clearCookie("auth_token");
    res.redirect("/login");
});

/* =========================
   STANDARD BROWSER LOGIN FORM HANDLER (FIXED FOR COOKIES)
========================= */
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

        // Generate Identity Verification Token
        const token = jwt.sign(
            { id: user.id, email: user.email, name: user.name }, 
            process.env.JWT_SECRET || "fallback_secret_key", 
            { expiresIn: "7d" }
        );

        // FIXED: Saves the token as a secure cookie in the user's browser automatically
        res.cookie("auth_token", token, {
            httpOnly: true, // Shields the cookie from malicious scripts
            secure: true,   // Transmits exclusively over secure HTTPS channels
            maxAge: 7 * 24 * 60 * 60 * 1000 // Lasts exactly 7 days
        });

        res.redirect("/dashboard");
    } catch (error) {
        res.status(500).send("Login error: " + error.message);
    }
});

/* =========================
   STANDARD BROWSER SIGNUP FORM HANDLER
========================= */
app.post("/signup", async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (!name || !email || !password) return res.status(400).send("All fields are required.");

        const [existingUsers] = await db.execute("SELECT id FROM users WHERE email = ?", [email]);
        if (existingUsers.length > 0) return res.status(400).send("Email already registered.");

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword]);
        
        res.redirect("/login");
    } catch (error) {
        res.status(500).send("Registration error: " + error.message);
    }
});
app.post("/register", async (req, res) => { res.redirect(307, "/signup"); });

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log("🚀 Secure single-user data partition system live on port " + PORT);
});
