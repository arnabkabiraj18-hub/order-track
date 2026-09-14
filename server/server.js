require('dotenv').config();

// ================= CRITICAL SECURITY ENV CHECK =================
if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
    console.error("❌ Fatal Error: Critical Security Environment Variables Missing!");
    process.exit(1);
}

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const pool = require('./db');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" }
});

// ================= ADVANCED FIREWALL & HARDENING =================
app.use(helmet());
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    credentials: true
}));

app.use(express.json({ limit: '10kb' }));

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 2000,
    message: { error: "Firewall Block: Too many requests from this IP. Try again later." }
});
app.use('/api/', globalLimiter);

const authLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 20,
    message: { error: "Security Alert: Too many login or OTP attempts. Please wait 10 minutes." }
});
app.use('/api/auth/', authLimiter);

// ================= AUTHENTICATION MIDDLEWARE =================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access token missing!" });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid or expired token!" });
        req.user = user;
        next();
    });
};

// ================= ENTERPRISE DB TABLES & PERFORMANCE INDEXING =================
async function initOrderTrackEnterpriseDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS restaurants (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                phone VARCHAR(20) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                image_url TEXT,
                subscription_status VARCHAR(50) DEFAULT 'ACTIVE',
                assigned_plan VARCHAR(50) DEFAULT 'Professional',
                plan_expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '365 days'),
                upi_id VARCHAR(100) DEFAULT 'restaurant@okaxis',
                charge_gst BOOLEAN DEFAULT FALSE,
                gstin VARCHAR(50),
                fssai_lic_no VARCHAR(50),
                trade_reg_no VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS restaurant_users (
                id SERIAL PRIMARY KEY,
                restaurant_id VARCHAR(64) REFERENCES restaurants(id) ON DELETE CASCADE,
                email VARCHAR(255) UNIQUE NOT NULL,
                phone VARCHAR(20) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR(50) DEFAULT 'Manager',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS phone_otps (
                identifier VARCHAR(255) PRIMARY KEY,
                otp_code VARCHAR(6) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS authorized_devices (
                id SERIAL PRIMARY KEY,
                restaurant_id VARCHAR(64) REFERENCES restaurants(id) ON DELETE CASCADE,
                device_uuid VARCHAR(255) UNIQUE NOT NULL,
                device_name VARCHAR(100),
                quick_pin_hash VARCHAR(255),
                role VARCHAR(50) DEFAULT 'Staff',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS menu_items (
                id SERIAL PRIMARY KEY,
                restaurant_id VARCHAR(64) REFERENCES restaurants(id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                category VARCHAR(100) NOT NULL,
                price NUMERIC(10, 2) NOT NULL,
                is_pantry BOOLEAN DEFAULT FALSE,
                available BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
                restaurant_id VARCHAR(64) REFERENCES restaurants(id) ON DELETE CASCADE,
                order_type VARCHAR(50) DEFAULT 'Dine-In',
                table_no VARCHAR(20) NOT NULL,
                item_name VARCHAR(255) NOT NULL,
                qty INT NOT NULL,
                price NUMERIC(10, 2) NOT NULL,
                status VARCHAR(50) DEFAULT 'Pending',
                payment VARCHAR(50) DEFAULT 'Unpaid',
                customer_name VARCHAR(100) DEFAULT 'Guest',
                customer_phone VARCHAR(20) DEFAULT 'N/A',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sales_invoices (
                id SERIAL PRIMARY KEY,
                restaurant_id VARCHAR(64) REFERENCES restaurants(id) ON DELETE CASCADE,
                invoice_no VARCHAR(100) UNIQUE NOT NULL,
                table_no VARCHAR(20),
                grand_total NUMERIC(10, 2) NOT NULL,
                payment_mode VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS support_tickets (
                id SERIAL PRIMARY KEY,
                restaurant_id VARCHAR(64) REFERENCES restaurants(id) ON DELETE CASCADE,
                restaurant_name VARCHAR(255),
                phone VARCHAR(20),
                issue_type VARCHAR(100),
                description TEXT,
                status VARCHAR(50) DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_restaurants_id ON restaurants(id);
            CREATE INDEX IF NOT EXISTS idx_restaurants_phone ON restaurants(phone);
            CREATE INDEX IF NOT EXISTS idx_users_email ON restaurant_users(email);
            CREATE INDEX IF NOT EXISTS idx_users_phone ON restaurant_users(phone);
            CREATE INDEX IF NOT EXISTS idx_devices_uuid ON authorized_devices(device_uuid);
            CREATE INDEX IF NOT EXISTS idx_orders_resto ON orders(restaurant_id);
        `);
        console.log("✅ All Enterprise Tables & High-Scale Indexes Verified Successfully!");
    } catch (e) {
        console.error("Database initialization error:", e.message);
    }
}
initOrderTrackEnterpriseDB();

// ================= AUTHENTICATION & OTP APIS =================

app.post('/api/auth/send-otp', async (req, res) => {
    const identifier = req.body.identifier?.trim();
    if (!identifier) return res.status(400).json({ error: "Phone number or email is required!" });

    try {
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        await pool.query(
            `INSERT INTO phone_otps (identifier, otp_code, expires_at, verified)
             VALUES ($1, $2, $3, FALSE)
             ON CONFLICT (identifier) DO UPDATE SET otp_code = $2, expires_at = $3, verified = FALSE`,
            [identifier, otpCode, expiresAt]
        );

        console.log(`📱 [OTP Gateway Simulation] Sent to ${identifier} -> Code: ${otpCode}`);
        res.json({ success: true, message: "OTP sent successfully." });
    } catch (err) {
        console.error("❌ Send OTP Error:", err.message);
        res.status(500).json({ error: "Internal Security Error." });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    const identifier = req.body.identifier?.trim();
    const otpCode = req.body.otpCode?.trim();

    if (!identifier || !otpCode) {
        return res.status(400).json({ error: "Identifier and OTP code are required!" });
    }

    try {
        const result = await pool.query("SELECT * FROM phone_otps WHERE identifier = $1", [identifier]);
        if (result.rows.length === 0) return res.status(400).json({ error: "OTP not requested or expired!" });

        const record = result.rows[0];
        if (new Date() > new Date(record.expires_at)) return res.status(400).json({ error: "OTP has expired!" });
        if (record.otp_code !== otpCode) return res.status(400).json({ error: "Incorrect OTP code!" });

        await pool.query("UPDATE phone_otps SET verified = TRUE WHERE identifier = $1", [identifier]);
        console.log(`✅ OTP Verified Successfully for identifier: ${identifier}`);
        res.json({ success: true, message: "OTP verified successfully!" });
    } catch (err) {
        console.error("❌ Verify OTP Error:", err.message);
        res.status(500).json({ error: "Internal Security Error." });
    }
});

app.post('/api/auth/register', async (req, res) => {
    const restaurantName = req.body.restaurantName?.trim();
    const phone = req.body.phone?.trim();
    const email = req.body.email?.trim().toLowerCase();
    const password = req.body.password;

    console.log("📥 Incoming Register Request:", { restaurantName, phone, email });

    if (!restaurantName || !phone || !email || !password) {
        return res.status(400).json({ error: "All fields are required!" });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const existingCheck = await client.query(
            "SELECT id FROM restaurants WHERE phone = $1 OR email = $2", 
            [phone, email]
        );
        if (existingCheck.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: "Number or email is already registered in the system!" });
        }

        const otpCheck = await client.query("SELECT * FROM phone_otps WHERE identifier = $1", [phone]);
        if (otpCheck.rows.length === 0 || !otpCheck.rows[0].verified) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: "Mobile number verification required via OTP before registration!" });
        }

        const restaurantId = 'REST_' + Date.now().toString(36);
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        await client.query(
            `INSERT INTO restaurants (id, name, phone, email, subscription_status)
             VALUES ($1, $2, $3, $4, 'ACTIVE')`,
            [restaurantId, restaurantName, phone, email]
        );

        await client.query(
            `INSERT INTO restaurant_users (restaurant_id, email, phone, password_hash, role)
             VALUES ($1, $2, $3, $4, 'MasterAdmin')`,
            [restaurantId, email, phone, passwordHash]
        );

        await client.query("DELETE FROM phone_otps WHERE identifier = $1", [phone]);
        await client.query('COMMIT');

        const token = jwt.sign(
            { email, restaurantId, role: 'MasterAdmin' },
            process.env.JWT_SECRET,
            { expiresIn: '30d' }
        );

        console.log(`🎉 Registration Successful for Restaurant ID: ${restaurantId}`);
        res.status(201).json({ success: true, token, restaurantId, message: "Registration successful!" });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("❌ Register Error Details:", err.message);
        res.status(500).json({ error: "Registration error encountered: " + err.message });
    } finally {
        client.release();
    }
});

app.post('/api/auth/login', async (req, res) => {
    const identifier = req.body.identifier?.trim();
    const password = req.body.password;

    if (!identifier || !password) {
        return res.status(400).json({ error: "Identifier and password are required!" });
    }

    try {
        const userRes = await pool.query(
            "SELECT * FROM restaurant_users WHERE email = $1 OR phone = $1", 
            [identifier]
        );

        if (userRes.rows.length === 0) {
            return res.status(400).json({ error: "User not found with this phone/email!" });
        }

        const user = userRes.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(400).json({ error: "Incorrect password!" });

        const token = jwt.sign(
            { email: user.email, restaurantId: user.restaurant_id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ success: true, token, restaurantId: user.restaurant_id, role: user.role });
    } catch (err) {
        console.error("❌ Login Error:", err.message);
        res.status(500).json({ error: "Login error encountered." });
    }
});

// ================= PUBLIC QR MENU & ORDERING APIS =================

app.get('/api/public/menu/:restaurantId', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM menu_items WHERE restaurant_id = $1 AND available = TRUE ORDER BY category, id", [req.params.restaurantId]);
        res.json({ success: true, menu: result.rows });
    } catch (err) {
        res.status(500).json({ error: "Menu fetch error." });
    }
});

app.post('/api/public/orders', async (req, res) => {
    const { restaurantId, tableNo, items, customerName, customerPhone } = req.body;
    if (!restaurantId || !tableNo || !items) {
        return res.status(400).json({ error: "Missing required order data!" });
    }

    try {
        const insertedOrders = [];
        for (const item of items) {
            const result = await pool.query(
                `INSERT INTO orders (restaurant_id, table_no, item_name, qty, price, status, payment, customer_name, customer_phone)
                 VALUES ($1, $2, $3, $4, $5, 'Pending', 'Unpaid', $6, $7) RETURNING *`,
                [restaurantId, tableNo, item.name, item.qty || 1, (item.price || 50) * (item.qty || 1), customerName || 'Guest', customerPhone || 'N/A']
            );
            insertedOrders.push(result.rows[0]);
        }

        io.to(`resto_${restaurantId}`).emit('new_order_placed', { tableNo, orders: insertedOrders });
        res.status(201).json({ success: true, orders: insertedOrders });
    } catch (err) {
        console.error("❌ Order Placement Error:", err.message);
        res.status(500).json({ error: "Order placement error." });
    }
});

// ================= KITCHEN MODULE APIS =================

app.get('/api/kitchen/orders/:restaurantId', async (req, res) => {
    try {
        const { restaurantId } = req.params;
        const result = await pool.query(
            "SELECT * FROM orders WHERE restaurant_id = $1 AND status != 'Completed' ORDER BY created_at DESC",
            [restaurantId]
        );
        res.json({ success: true, orders: result.rows });
    } catch (err) {
        console.error("❌ Kitchen Orders Error:", err.message);
        res.status(500).json({ error: "Failed to fetch kitchen orders." });
    }
});

app.patch('/api/kitchen/order-status', async (req, res) => {
    try {
        const { orderId, status } = req.body;
        if (!orderId || !status) {
            return res.status(400).json({ error: "Order ID and status are required!" });
        }
        await pool.query("UPDATE orders SET status = $1 WHERE id = $2", [status, orderId]);
        res.json({ success: true, message: "Order status updated successfully." });
    } catch (err) {
        console.error("❌ Update Order Status Error:", err.message);
        res.status(500).json({ error: "Failed to update order status." });
    }
});

// ================= ADMIN MODULE APIS =================

app.get('/api/admin/menu/:restaurantId', async (req, res) => {
    try {
        const { restaurantId } = req.params;
        const result = await pool.query("SELECT * FROM menu_items WHERE restaurant_id = $1 ORDER BY id DESC", [restaurantId]);
        res.json({ success: true, menu: result.rows });
    } catch (err) {
        console.error("❌ Admin Menu Fetch Error:", err.message);
        res.status(500).json({ error: "Failed to fetch admin menu." });
    }
});

app.post('/api/admin/menu', async (req, res) => {
    try {
        const { restaurantId, name, category, price, isAvailable } = req.body;
        if (!restaurantId || !name || !category || price === undefined) {
            return res.status(400).json({ error: "Required menu fields are missing!" });
        }
        const result = await pool.query(
            `INSERT INTO menu_items (restaurant_id, name, category, price, available) 
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [restaurantId, name, category, price, isAvailable ?? true]
        );
        res.status(201).json({ success: true, item: result.rows[0] });
    } catch (err) {
        console.error("❌ Add Menu Item Error:", err.message);
        res.status(500).json({ error: "Failed to add menu item." });
    }
});

app.put('/api/admin/menu/:itemId', async (req, res) => {
    try {
        const { itemId } = req.params;
        const { name, category, price, available } = req.body;
        const result = await pool.query(
            `UPDATE menu_items SET name = COALESCE($1, name), category = COALESCE($2, category), 
             price = COALESCE($3, price), available = COALESCE($4, available) WHERE id = $5 RETURNING *`,
            [name, category, price, available, itemId]
        );
        res.json({ success: true, item: result.rows[0] });
    } catch (err) {
        console.error("❌ Update Menu Item Error:", err.message);
        res.status(500).json({ error: "Failed to update menu item." });
    }
});

app.delete('/api/admin/menu/:itemId', async (req, res) => {
    try {
        const { itemId } = req.params;
        await pool.query("DELETE FROM menu_items WHERE id = $1", [itemId]);
        res.json({ success: true, message: "Menu item deleted successfully." });
    } catch (err) {
        console.error("❌ Delete Menu Item Error:", err.message);
        res.status(500).json({ error: "Failed to delete menu item." });
    }
});

app.get('/api/admin/stats/:restaurantId', async (req, res) => {
    try {
        const { restaurantId } = req.params;
        const salesRes = await pool.query("SELECT SUM(grand_total) as total_sales FROM sales_invoices WHERE restaurant_id = $1", [restaurantId]);
        const ordersRes = await pool.query("SELECT COUNT(*) as total_orders FROM orders WHERE restaurant_id = $1", [restaurantId]);
        res.json({
            success: true,
            totalSales: salesRes.rows[0].total_sales || 0,
            totalOrders: ordersRes.rows[0].total_orders || 0
        });
    } catch (err) {
        console.error("❌ Admin Stats Error:", err.message);
        res.status(500).json({ error: "Failed to fetch admin stats." });
    }
});

// ================= BILLING MODULE APIS =================

app.get('/api/billing/orders/:restaurantId', async (req, res) => {
    try {
        const { restaurantId } = req.params;
        const result = await pool.query("SELECT * FROM orders WHERE restaurant_id = $1 AND payment = 'Unpaid' ORDER BY created_at DESC", [restaurantId]);
        res.json({ success: true, orders: result.rows });
    } catch (err) {
        console.error("❌ Billing Orders Error:", err.message);
        res.status(500).json({ error: "Failed to fetch billing orders." });
    }
});

app.post('/api/billing/checkout', async (req, res) => {
    try {
        const { orderId, amount, paymentMethod } = req.body;
        if (!orderId || !amount) {
            return res.status(400).json({ error: "Order ID and amount are required!" });
        }

        const invoiceNo = 'INV_' + Date.now();
        const orderRes = await pool.query("SELECT * FROM orders WHERE id = $1", [orderId]);
        if (orderRes.rows.length === 0) return res.status(404).json({ error: "Order not found." });
        const order = orderRes.rows[0];

        await pool.query("UPDATE orders SET payment = 'Paid', status = 'Completed' WHERE id = $1", [orderId]);
        
        await pool.query(
            `INSERT INTO sales_invoices (restaurant_id, invoice_no, table_no, grand_total, payment_mode) 
             VALUES ($1, $2, $3, $4, $5)`,
            [order.restaurant_id, invoiceNo, order.table_no, amount, paymentMethod || 'Cash']
        );

        res.json({ success: true, invoiceId: invoiceNo, message: "Payment processed successfully." });
    } catch (err) {
        console.error("❌ Checkout Error:", err.message);
        res.status(500).json({ error: "Payment checkout failed." });
    }
});

// ================= WAITER MODULE APIS =================

app.post('/api/waiter/orders', async (req, res) => {
    try {
        const { restaurantId, tableNo, items } = req.body;
        if (!restaurantId || !tableNo || !items) {
            return res.status(400).json({ error: "Missing required waiter order data!" });
        }

        const insertedOrders = [];
        for (const item of items) {
            const result = await pool.query(
                `INSERT INTO orders (restaurant_id, table_no, item_name, qty, price, status, payment, customer_name, customer_phone)
                 VALUES ($1, $2, $3, $4, $5, 'Pending', 'Unpaid', 'Waiter Order', 'N/A') RETURNING *`,
                [restaurantId, tableNo, item.name, item.qty || 1, (item.price || 50) * (item.qty || 1)]
            );
            insertedOrders.push(result.rows[0]);
        }

        io.to(`resto_${restaurantId}`).emit('new_order_placed', { tableNo, orders: insertedOrders });
        res.status(201).json({ success: true, orderId: insertedOrders[0]?.id, orders: insertedOrders });
    } catch (err) {
        console.error("❌ Waiter Order Error:", err.message);
        res.status(500).json({ error: "Waiter order creation failed." });
    }
});

// ================= SOCKET.IO REALTIME ROOMS =================
io.on('connection', (socket) => {
    socket.on('join_restaurant', (restaurantId) => {
        socket.join(`resto_${restaurantId}`);
    });
});

// ================= PRODUCTION ERROR MASKING MIDDLEWARE =================
app.use((err, req, res, next) => {
    console.error("🔒 Security Error Log:", err.message);
    res.status(500).json({ error: "Internal Security Error. Request blocked." });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`🚀 OrderTrack High-Scale Enterprise Server running on port ${PORT}`);
});