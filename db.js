require("dotenv").config();

const mysql = require("mysql2");

const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

connection.connect((error) => {
    if (error) {
        console.error("❌ MySQL connection failed:");
        console.error(error.message);
        return;
    }

    console.log("✅ Connected to MySQL database!");
});

// FIXED: Prevents Node app from crashing if MySQL disconnects due to inactivity
connection.on("error", (error) => {
    console.error("⚠️ Database error occurred:", error.message);
    if (error.code === "PROTOCOL_CONNECTION_LOST") {
        console.error("❌ Database connection lost.");
    }
});

module.exports = connection;

