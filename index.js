import express from 'express';
import mysql2 from 'mysql2/promise';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import session from 'express-session'; 
import passport from 'passport'; 
import { Strategy as LocalStrategy } from 'passport-local';

dotenv.config();
const app = express();
const port = 3000;

app.use(cors({
    origin: 'http://localhost:5173', 
    credentials: true
}));
app.use(express.json());

const db = mysql2.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

app.use(session({
    secret: process.env.SECRET_SESSION || 'BE_Instockfow_Secret', 
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, 
        httpOnly: true,
        maxAge: 60 * 60 * 1000 
    }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    async (email, password, done) => {
        try {
            const [users] = await db.query('SELECT * FROM users WHERE email = ? OR username = ?', [email, email]);
            if (users.length === 0) {
                return done(null, false, { message: 'Akun tidak ditemukan!' });
            }
            
            const user = users[0];
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return done(null, false, { message: 'Password salah!' });
            }
            
            return done(null, user); 
        } catch (error) {
            return done(error);
        }
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const [rows] = await db.query('SELECT id, username, email FROM users WHERE id = ?', [id]);
        if (rows.length === 0) return done(null, false);
        done(null, rows[0]);
    } catch (error) {
        done(error);
    }
});

const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ message: 'Akses ditolak! Anda harus login terlebih dahulu.' });
};

app.get('/api/products', isAuthenticated, async(req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM products');
        res.json(rows)
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/suppliers', isAuthenticated, async(req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM suppliers');
        res.json(rows);
    } catch (error) {
        res.status(500).json({message: error.message});
    }
});

app.get('/api/users/me', (req, res) => {
    if (req.isAuthenticated()) {
        res.json(req.user);
    } else {
        res.status(401).json({ message: 'Belum login' });
    }
});

app.post('/api/products', async(req, res) => {
    const {name, category, stock, price, supplier} = req.body;
    try {
        const query = 'INSERT INTO products (name, category, stock, price, supplier) VALUES(?, ?, ?, ?, ?)';
        const [result] = await db.query(query, [name, category, stock, price, supplier]);
        res.status(201).json({id : result.insertId, name, category, stock, price, supplier});
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.put('/api/products/:id', async(req, res) => {
    const {id} = req.params;
    const { name, category, stock, price, supplier } = req.body;
    try {
        const query = 'UPDATE products SET name = ?, category = ?, stock = ?, price = ?, supplier = ? WHERE id = ?';
        await db.query(query, [name, category, stock, price, supplier, id]);
        res.json({ message: 'Produk berhasil diperbarui' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.delete('/api/products/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const query = 'DELETE FROM products WHERE id = ?';
        await db.query(query, [id]);
        res.json({ message: 'Produk berhasil dihapus' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/suppliers', async (req, res) => {
    const { supplier, industry, email, phone } = req.body;
    try {
        const query = 'INSERT INTO suppliers (supplier, industry, email, phone) VALUES (?, ?, ?, ?)';
        const [result] = await db.query(query, [supplier, industry, email, phone]);
        
        res.status(201).json({ id: result.insertId, supplier, industry, email, phone });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.put('/api/suppliers/:id', async (req, res) => {
    const { id } = req.params;
    const { supplier, industry, email, phone } = req.body;
    try {
        const query = 'UPDATE suppliers SET supplier = ?, industry = ?, email = ?, phone = ? WHERE id = ?';
        await db.query(query, [supplier, industry, email, phone, id]);
        res.json({ message: 'Data supplier berhasil diperbarui' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.delete('/api/suppliers/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const query = 'DELETE FROM suppliers WHERE id = ?';
        await db.query(query, [id]);
        res.json({ message: 'Supplier berhasil dihapus' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/register', async(req, res) => {
    const { username, email, password } = req.body;
    try {
        const [existingUser] = await db.query('SELECT id FROM users WHERE email = ? OR username = ?', [email, username]);
        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'Username atau Email sudah terdaftar!' });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        await db.query(query, [username, email, hashedPassword]);

        res.status(201).json({ message: 'Registrasi berhasil!' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return res.status(500).json({ message: err.message });
        if (!user) return res.status(401).json({ message: info.message });
        
        req.logIn(user, (err) => {
            if (err) return res.status(500).json({ message: err.message });
            return res.json({
                message: 'Login sukses!',
                user: { id: user.id, username: user.username, email: user.email }
            });
        });
    })(req, res, next);
});

app.post('/api/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return res.status(500).json({ message: err.message });
        req.session.destroy(() => {
            res.json({ message: 'Berhasil hancurkan session server, silakan keluar.' });
        });
    });
});

app.use((req, res) => {
    res.status(404).json({
        status: 404,
        message: `Rute API [${req.method}] ${req.originalUrl} tidak ditemukan di server!`
    });
});

app.listen(port, () => {
    console.log(`Server running is port ${port}`);
});