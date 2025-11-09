const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const csurf = require('csurf');

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: 'dev-secret-please-change', resave: false, saveUninitialized: true }));
app.use(express.static(path.join(__dirname, 'public')));


const DB_FILE = path.join(__dirname, 'data.db');
const db = new sqlite3.Database(DB_FILE);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, pin TEXT, email TEXT, note TEXT)`);
  db.run(`INSERT OR IGNORE INTO users (username, pin, email, note) VALUES ('admin','1234','admin@example.com','Original admin note')`);
});


const csrfProtection = csurf({ cookie: false });


app.use((req, res, next) => {
  if (!req.session.flags) {
   
    req.session.flags = { sqli: true, csrf: true };
  }
  next();
});


app.post('/toggle', (req, res) => {
  const { sqli, csrf } = req.body;
  req.session.flags.sqli = !!(sqli === 'on' || sqli === 'true' || sqli === '1');
  req.session.flags.csrf = !!(csrf === 'on' || csrf === 'true' || csrf === '1');
  res.redirect('/');
});


app.get('/', (req, res) => {
  
  db.get(`SELECT username, email, note FROM users WHERE username = ?`, ['admin'], (err, row) => {
    if (err) { row = { username: 'admin', email: 'error', note: 'db error' }; }
    res.render('index', {
      flags: req.session.flags,
      admin: row,
      csrfToken: req.csrfToken ? req.csrfToken() : null
    });
  });
});

// sql injection
app.post('/login', (req, res) => {
  const { username, pin } = req.body;
  if (req.session.flags.sqli) {
    // slab na sql injectione
    const sql = `SELECT * FROM users WHERE username = '${username}' AND pin = '${pin}'`;
    db.get(sql, [], (err, row) => {
      if (row) {
        req.session.user = row.username;
        res.render('result', { title: 'Login uspjeh (vulnerable)', msg: `Uspješno ste prijavljeni kao ${row.username}. Upit: ${sql}` });
      } else {
        res.render('result', { title: 'Login neuspjeh (vulnerable)', msg: `Neuspjeli login. Upit: ${sql}` });
      }
    });
  } else {
    // siguran od sql injectiona
    const sql = `SELECT * FROM users WHERE username = ? AND pin = ?`;
    db.get(sql, [username, pin], (err, row) => {
      if (row) {
        req.session.user = row.username;
        res.render('result', { title: 'Login uspjeh (safe)', msg: `Uspješno ste prijavljeni kao ${row.username}.` });
      } else {
        res.render('result', { title: 'Login neuspjeh (safe)', msg: `Neuspjeli login.` });
      }
    });
  }
});

// CSRF 
app.post('/change-note', (req, res, next) => {
  // bez csrf checka
  if (req.session.flags.csrf) {
    
    const { note } = req.body;
    db.run(`UPDATE users SET note = ? WHERE username = 'admin'`, [note], (err) => {
      res.render('result', { title: 'Note promijenjena (vulnerable)', msg: `Admin note postavljena na: ${note}` });
    });
  } else {
    // sa csrf checkom
    csrfProtection(req, res, function(err) {
      if (err) return next(err);
      const { note } = req.body;
      db.run(`UPDATE users SET note = ? WHERE username = 'admin'`, [note], (err) => {
        res.render('result', { title: 'Note promijenjena (safe)', msg: `Admin note postavljena na: ${note}` });
      });
    });
  }
});


app.get('/attacker', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'attacker.html'));
});


app.get('/flags', (req, res) => {
  res.json(req.session.flags);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`App listening on port ${PORT}`));
