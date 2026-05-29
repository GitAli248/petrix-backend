const Database = require('better-sqlite3');
const path = require('path');
const dbPath = path.join(__dirname, 'users.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
db.exec('CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE NOT NULL, full_name TEXT DEFAULT "", phone TEXT DEFAULT "", addresses TEXT DEFAULT "[]", FOREIGN KEY (user_id) REFERENCES users(id))');
module.exports = db;
