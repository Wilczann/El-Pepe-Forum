const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'forum.db');

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
    process.exit(1);
  }

  console.log('Connected to SQLite database.');

  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author TEXT NOT NULL,
        text TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
  });
});

function sendJsonError(res, status, message) {
  res.status(status).json({ error: message });
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, message: 'El Pepe Forum API działa' });
});

app.post('/api/register', (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();

  if (!username || !password) {
    sendJsonError(res, 400, 'Uzupełnij nazwę użytkownika i hasło.');
    return;
  }

  if (username.length < 3) {
    sendJsonError(res, 400, 'Nazwa użytkownika musi mieć co najmniej 3 znaki.');
    return;
  }

  if (password.length < 4) {
    sendJsonError(res, 400, 'Hasło musi mieć co najmniej 4 znaki.');
    return;
  }

  db.get('SELECT id FROM users WHERE LOWER(username) = LOWER(?)', [username], (err, row) => {
    if (err) {
      sendJsonError(res, 500, 'Błąd odczytu użytkowników.');
      return;
    }

    if (row) {
      sendJsonError(res, 409, 'Ta nazwa użytkownika już istnieje.');
      return;
    }

    const passwordHash = bcrypt.hashSync(password, 10);

    db.run(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash],
      function (insertErr) {
        if (insertErr) {
          sendJsonError(res, 500, 'Nie udało się utworzyć konta.');
          return;
        }

        res.status(201).json({ ok: true, username });
      }
    );
  });
});

app.post('/api/login', (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();

  if (!username || !password) {
    sendJsonError(res, 400, 'Uzupełnij nazwę użytkownika i hasło.');
    return;
  }

  db.get('SELECT id, username, password_hash FROM users WHERE LOWER(username) = LOWER(?)', [username], (err, user) => {
    if (err) {
      sendJsonError(res, 500, 'Błąd logowania.');
      return;
    }

    if (!user) {
      sendJsonError(res, 401, 'Błędna nazwa użytkownika lub hasło.');
      return;
    }

    const isValid = bcrypt.compareSync(password, user.password_hash);
    if (!isValid) {
      sendJsonError(res, 401, 'Błędna nazwa użytkownika lub hasło.');
      return;
    }

    res.json({ ok: true, username: user.username });
  });
});

app.get('/api/posts', (req, res) => {
  db.all(
    'SELECT id, author, text, created_at AS createdAt FROM posts ORDER BY created_at DESC',
    [],
    (err, rows) => {
      if (err) {
        sendJsonError(res, 500, 'Błąd odczytu postów.');
        return;
      }

      res.json({ ok: true, posts: rows });
    }
  );
});

app.post('/api/posts', (req, res) => {
  const author = String(req.body?.author || '').trim();
  const text = String(req.body?.text || '').trim();

  if (!author || !text) {
    sendJsonError(res, 400, 'Wpisz treść posta.');
    return;
  }

  db.run(
    'INSERT INTO posts (author, text) VALUES (?, ?)',
    [author, text],
    function (err) {
      if (err) {
        sendJsonError(res, 500, 'Nie udało się zapisać posta.');
        return;
      }

      res.status(201).json({ ok: true, id: this.lastID, author, text });
    }
  );
});

app.delete('/api/posts/:id', (req, res) => {
  const postId = Number(req.params.id);
  const author = String(req.body?.author || '').trim();

  if (!Number.isInteger(postId) || postId <= 0) {
    sendJsonError(res, 400, 'Nieprawidłowy identyfikator posta.');
    return;
  }

  db.get('SELECT author FROM posts WHERE id = ?', [postId], (err, row) => {
    if (err) {
      sendJsonError(res, 500, 'Błąd usuwania posta.');
      return;
    }

    if (!row) {
      sendJsonError(res, 404, 'Post nie istnieje.');
      return;
    }

    if (row.author !== author) {
      sendJsonError(res, 403, 'Nie możesz usunąć tego posta.');
      return;
    }

    db.run('DELETE FROM posts WHERE id = ?', [postId], function (deleteErr) {
      if (deleteErr) {
        sendJsonError(res, 500, 'Nie udało się usunąć posta.');
        return;
      }

      res.json({ ok: true, deletedId: postId });
    });
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`El Pepe Forum API działa na http://localhost:${PORT}`);
});
