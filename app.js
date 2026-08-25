require("dotenv").config();

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const connection = require("./db");

const app = express();


// ==========================================
// MIDDLEWARE
// ==========================================

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
    express.static(path.join(__dirname, "public"))
);

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            maxAge: 1000 * 60 * 60 * 24
        }
    })
);


// ==========================================
// EJS
// ==========================================

app.set("view engine", "ejs");


// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================

function requireLogin(req, res, next) {

    if (!req.session.userId) {
        return res.redirect("/login");
    }

    next();
}


// ==========================================
// SIGN UP PAGE
// ==========================================

app.get("/signup", (req, res) => {

    if (req.session.userId) {
        return res.redirect("/");
    }

    res.render("signup");
});


// ==========================================
// SIGN UP
// ==========================================

app.post("/signup", async (req, res) => {

    const {
        name,
        email,
        password
    } = req.body;

    if (!name || !email || !password) {
        return res.status(400).send(
            "All fields are required."
        );
    }

    if (password.length < 6) {
        return res.status(400).send(
            "Password must contain at least 6 characters."
        );
    }

    try {

        const hashedPassword =
            await bcrypt.hash(password, 10);

        const sql = `
            INSERT INTO users
            (name, email, password)
            VALUES (?, ?, ?)
        `;

        connection.query(
            sql,
            [
                name.trim(),
                email.trim().toLowerCase(),
                hashedPassword
            ],
            (error) => {

                if (error) {

                    if (error.code === "ER_DUP_ENTRY") {

                        return res.send(`
                            <h2>Email already registered.</h2>
                            <a href="/login">Go to Login</a>
                        `);
                    }

                    console.error(error);

                    return res.status(500).send(
                        "Error creating account."
                    );
                }

                res.redirect("/login");
            }
        );

    } catch (error) {

        console.error(error);

        res.status(500).send(
            "Error creating account."
        );
    }
});


// ==========================================
// LOGIN PAGE
// ==========================================

app.get("/login", (req, res) => {

    if (req.session.userId) {
        return res.redirect("/");
    }

    res.render("login");
});


// ==========================================
// LOGIN
// ==========================================

app.post("/login", (req, res) => {

    const {
        email,
        password
    } = req.body;

    if (!email || !password) {
        return res.status(400).send(
            "Email and password are required."
        );
    }

    const sql = `
        SELECT *
        FROM users
        WHERE email = ?
    `;

    connection.query(
        sql,
        [email.trim().toLowerCase()],
        async (error, results) => {

            if (error) {

                console.error(error);

                return res.status(500).send(
                    "Login error."
                );
            }

            if (results.length === 0) {

                return res.send(`
                    <h2>Invalid email or password.</h2>
                    <a href="/login">Try again</a>
                `);
            }

            const user = results[0];

            const passwordMatch =
                await bcrypt.compare(
                    password,
                    user.password
                );

            if (!passwordMatch) {

                return res.send(`
                    <h2>Invalid email or password.</h2>
                    <a href="/login">Try again</a>
                `);
            }

            req.session.userId = user.id;
            req.session.userName = user.name;
            req.session.userEmail = user.email;

            res.redirect("/");
        }
    );
});


// ==========================================
// LOGOUT
// ==========================================

app.post("/logout", (req, res) => {

    req.session.destroy((error) => {

        if (error) {
            console.error(error);
        }

        res.redirect("/login");
    });
});


// ==========================================
// DASHBOARD / HOME
// ==========================================

app.get("/", requireLogin, (req, res) => {

    const sql = `
        SELECT *
        FROM tasks
        WHERE user_id = ?
        ORDER BY
            CASE
                WHEN status = 'Pending' THEN 0
                ELSE 1
            END,
            created_at DESC
    `;

    connection.query(
        sql,
        [req.session.userId],
        (error, results) => {

            if (error) {

                console.error(error);

                return res.status(500).send(
                    "Error fetching tasks."
                );
            }

            res.render("index", {
                tasks: results,
                user: {
                    name: req.session.userName,
                    email: req.session.userEmail
                }
            });
        }
    );
});


// ==========================================
// ADD TASK PAGE
// ==========================================

app.get("/add-task", requireLogin, (req, res) => {

    res.render("add-task");
});


// ==========================================
// ADD TASK
// ==========================================

app.post("/add-task", requireLogin, (req, res) => {

    const {
        title,
        description,
        due_date,
        priority
    } = req.body;

    if (!title || title.trim() === "") {

        return res.status(400).send(
            "Task title is required."
        );
    }

    const sql = `
        INSERT INTO tasks
        (
            user_id,
            title,
            description,
            due_date,
            priority
        )
        VALUES (?, ?, ?, ?, ?)
    `;

    connection.query(
        sql,
        [
            req.session.userId,
            title.trim(),
            description || null,
            due_date || null,
            priority || "Medium"
        ],
        (error) => {

            if (error) {

                console.error(error);

                return res.status(500).send(
                    "Error adding task."
                );
            }

            res.redirect("/");
        }
    );
});


// ==========================================
// EDIT TASK PAGE
// ==========================================

app.get(
    "/edit-task/:id",
    requireLogin,
    (req, res) => {

        const taskId = req.params.id;

        const sql = `
            SELECT *
            FROM tasks
            WHERE id = ?
            AND user_id = ?
        `;

        connection.query(
            sql,
            [
                taskId,
                req.session.userId
            ],
            (error, results) => {

                if (error) {

                    console.error(error);

                    return res.status(500).send(
                        "Error fetching task."
                    );
                }

                if (results.length === 0) {

                    return res.status(404).send(
                        "Task not found."
                    );
                }

                // FIXED: Correctly pass the task object and close open callbacks
                res.render("edit-task", { task: results[0] });
            }
        );
    }
);


// ==========================================
// START SERVER
// ==========================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
