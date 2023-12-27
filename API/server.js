'use strict';
var http = require('http');
var port = process.env.PORT || 1337;

const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const app = express();
const jwt = require('jsonwebtoken'); 
const bcrypt = require('bcrypt');



app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

//логин
app.post('/users/login', async (req, res) => {
    try {
        let sql = `SELECT * FROM users WHERE name = ?`;
        let inserts = [req.body.name];
        db.get(sql, inserts, async function (err, row) {
            if (err) {
                console.error(err.message);
            }
            if (row) {
                const validPass = await bcrypt.compare(req.body.pass, row.pass);
                if (!validPass) {
                    return res.status(401).send("incorrect data");
                }
                let payload = { id: row.id, name: row.name, role: row.role };
                const token = jwt.sign(payload, 'token', { expiresIn: '1h' });

                res.setHeader("auth-token", token);
                res.status(200).send({ "token": token });
            } else {
                res.status(401).send('Invalid username')
            }
        });
    } catch (err) {
        console.log(err);
        res.status(500).send("An error occurred during login");
    }
});




app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const sqlite3 = require('sqlite3').verbose();

let db = new sqlite3.Database('./db.sqlite', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the SQLite database.');
});

// таблица для хранения продуктов
db.run(`CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  price REAL)`, (err) => {
    if (err) {
        console.error(err.message);
    }
});
//дроп пользователей
/*
db.run('DROP TABLE users', (err) => {
    if (err) {
        console.error(err.message);
    }
});
*/

// таблица пользователей
db.run(`CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT,
 surname TEXT,
 patronymic TEXT,
 city TEXT,
 role TEXT,
 pass TEXT)`, (err) => {
    if (err) {
        console.error(err.message);
    }
});


// массив для хранения данных
let products = [];

// путь для получения списка всех продуктов
app.get('/products', (req, res) => {
    let sql = `SELECT * FROM products`;
    db.all(sql, [], (err, rows) => {
        if (err) {
            return console.error(err.message);
        }
        res.json(rows);
    });
});

// путь для получения информации о продукте по ID
app.get('/products/:id', (req, res) => {
    let productId = req.params.id;
    let sql = `SELECT * FROM products WHERE id = ?`;
    db.get(sql, [productId], (err, row) => {
        if (err) {
            return console.error(err.message);
        }
        res.json(row);
    });
});


// путь для добавления нового продукта
/*
app.post('/products', (req, res) => {
    let newProduct = req.body;
    let sql = `INSERT INTO products(title, price) VALUES(?, ?)`;
    let inserts = [newProduct.title, newProduct.price];
    db.run(sql, inserts, function (err) {
        if (err) {
            return console.error(err.message);
        }
        res.status(201).json(newProduct);
    });
});
*/

// путь для обновления информации о продукте
/*
app.put('/products/:id', (req, res) => {
    let productId = req.params.id;
    let updatedProduct = req.body;
    let sql = `UPDATE products SET title = ?, price = ? WHERE id = ?`;
    db.run(sql, [updatedProduct.title, updatedProduct.price, productId], function (err) {
        if (err) {
            return console.error(err.message);
        }
        res.json(updatedProduct);
    });
});
*/

// путь для удаления 
/*
app.delete('/products/dell/:id', (req, res) => {
    let productId = req.params.id;
    let sql = `DELETE FROM products WHERE id = ?`;
    db.run(sql, [productId], function (err) {
        if (err) {
            return console.error(err.message);
        }
        res.json({ message: 'Product deleted successfully' });
    });
});
*/

// путь для регистрации нового пользователя
app.post('/users/register', (req, res) => {
    let newUser = req.body;
    let salt = bcrypt.genSaltSync(10);
    let hash = bcrypt.hashSync(newUser.pass, salt);
    let sql = `INSERT INTO users(name, surname, patronymic, city, role, pass) VALUES(?, ?, ?, ?, ?, ?)`;
    let inserts = [newUser.name, newUser.surname, newUser.patronymic, newUser.city, newUser.role, hash];
    db.run(sql, inserts, function (err) {
        if (err) {
            return console.error(err.message);
        }
        // Генерируем токен для нового пользователя
        let token = generateAccessToken(this.lastID);
        res.status(201).json({ message: 'successfully', token: token });
    });
});




// путь для аутентификации пользователя
app.post('/users/login', (req, res) => {
    let userdata = req.body;
    let sql = `SELECT * FROM users WHERE name = ? AND pass = ?`;
    let inserts = [userdata.name, userdata.pass];
    db.get(sql, inserts, function (err, row) {
        if (err) {
            return console.error(err.message);
        }
        if (row) {
            let token = generateAccessToken(row.id);
            res.json({ token: token });
        } else {
            res.status(401).json({ message: 'user or password err' });
        }
    });
});


// генерация токена
function generateAccessToken(userId) {
    return jwt.sign({ userId }, 'token', { expiresIn: '1h' });
}

// проверка токена
function authenticateToken(req, res, next) {
    let token = req.headers['auth-token'];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, 'token', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// проверка роли
function checkAdmin(req, res, next) {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    next();
}
function IsAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).send("not admin");
    }
}


// путь для добавления нового продукта (только админы)
app.post('/products', authenticateToken, IsAdmin, (req, res) => {
    let newProduct = req.body;
    let sql = `INSERT INTO products(title, price) VALUES(?, ?)`;
    let inserts = [newProduct.title, newProduct.price];
    db.run(sql, inserts, function (err) {
        if (err) {
            return console.error(err.message);
        }
        res.status(201).json(newProduct);
    });
});

// путь для обновления информации о продукте (только админы)
app.put('/products/:id', authenticateToken, IsAdmin, (req, res) => {
    let productId = req.params.id;
    let updatedProduct = req.body;
    let sql = `UPDATE products SET title = ?, price = ? WHERE id = ?`;
    let inserts = [updatedProduct.title, updatedProduct.price, productId];
    db.run(sql, inserts, function (err) {
        if (err) {
            return console.error(err.message);
        }
        res.json(updatedProduct);
    });
});

// путь для удаления продукта (только админы)
app.delete('/products/:id', authenticateToken, IsAdmin, (req, res) => {
    let productId = req.params.id;
    let sql = `DELETE FROM products WHERE id = ?`;
    db.run(sql, [productId], function (err) {
        if (err) {
            return console.error(err.message);
        }
        res.json({ message: 'product deleted' });
    });
});


app.listen(3000, () => console.log('Server started'));

http.createServer(function (req, res) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Omega API\n Go to 3000 port :)');
}).listen(port);
