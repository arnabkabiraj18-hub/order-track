require('dotenv').config();

// ================= CRITICAL SECURITY ENV CHECK =================
if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
    console.error("❌ Fatal Error: Critical Security Environment Variables Missing!");
    process.exit(1);
}

const express = require('express');
const compression = require('compression');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const path = require('path');

const pool = require('./db');

const app = express();
app.use(compression());

// স্ট্যাটিক ফাইল ও রুট রাউট
app.use(express.static(path.join(__dirname, '../')));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../src/admin/index.html'));
});

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: ["http://localhost:3000", "http://localhost:5500", "http://127.0.0.1:5500", "https://order-track-qibw.onrender.com"] }
});

// ================= ADVANCED FIREWALL & HARDENING =================
app.use(helmet());
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500', 'https://order-track-qibw.onrender.com'],
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
    max: 50,
    message: { error: "Security Alert: Too many login or OTP attempts. Please wait 10 minutes." }
});
app.use('/api/auth/', authLimiter);

// ================= AUTHENTICATION MIDDLEWARE =================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Fixed token index
    if (!token) return res.status(401).json({ error: "Access token missing!" });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid or expired token!" });
        req.user = user;
        next();
    });
};

// ================= SUBSCRIPTION VERIFICATION MIDDLEWARE =================
const verifySubscription = async (req, res, next) => {
    try {
        const restaurant_id = req.body.restaurant_id || req.headers['x-restaurant-id'] || req.query.restaurant_id || req.params.restaurantId;
        if (!restaurant_id) {
            return res.status(400).json({ error: "Restaurant ID is required for verification." });
        }
        const result = await pool.query(
            "SELECT subscription_status, plan_expires_at, assigned_plan FROM restaurants WHERE id = $1",
            [restaurant_id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Restaurant not found." });
        }
        const restaurant = result.rows[0];
        const now = new Date();
        const expiresAt = new Date(restaurant.plan_expires_at);

        if (restaurant.subscription_status !== 'ACTIVE' || expiresAt < now) {
            return res.status(403).json({ 
                error: "Your subscription has expired or is inactive. Please renew your plan." 
            });
        }
        req.assignedPlan = restaurant.assigned_plan;
        next();
    } catch (err) {
        console.error("Subscription Verification Error:", err);
        res.status(500).json({ error: "Internal server error during subscription check." });
    }
};

// ================= ENTERPRISE DB TABLES & PERFORMANCE INDEXING =================
async function initOrderTrackEnterpriseDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS subscription_plans (
                plan_name VARCHAR(100) PRIMARY KEY,
                price NUMERIC(10,2) DEFAULT 0,
                duration_days INT DEFAULT 365,
                max_staff INT DEFAULT 5,
                description TEXT
            );

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

        // ডিফল্ট প্ল্যান সিড করা (না থাকলে)
        await pool.query(`
            INSERT INTO subscription_plans (plan_name, price, duration_days, max_staff, description)
            VALUES 
            ('Starter', 399.00, 365, 5, 'Digital QR Standees, Up to 50 Menu Items, Daily Revenue Reports'),
            ('Professional', 999.00, 365, 15, 'Unlimited Menu & Modifiers, 360° Floor Heatmap Radar, 15 Waiter + 4 KDS Terminals, 24/7 Priority Emergency Support'),
            ('Enterprise', 2999.00, 365, 50, 'Multi-Branch Central Ledger, Custom ERP & Tally Bridge, Dedicated Operations Manager')
            ON CONFLICT (plan_name) DO NOTHING;
        `);

        console.log("✅ All Enterprise Tables, Indexes & Seed Plans Verified Successfully!");
    } catch (e) {
        console.error("Database initialization error:", e.message);
    }
}
initOrderTrackEnterpriseDB();

// ================= AUTHENTICATION & OTP APIS (DEV & PRODUCTION READY) =================
app.post('/api/auth/send-otp', async (req, res) => {
    const identifier = req.body.identifier?.trim();
    if (!identifier) return res.status(400).json({ error: "Phone number or email is required!" });

    try {
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

        await pool.query(
            `INSERT INTO phone_otps (identifier, otp_code, expires_at, verified)
             VALUES ($1, $2, $3, FALSE)
             ON CONFLICT (identifier) DO UPDATE SET otp_code = $2, expires_at = $3, verified = FALSE`,
            [identifier, otpCode, expiresAt]
        );

        console.log(`📱 [TEST/DEV OTP] Identifier: ${identifier} -> OTP: ${otpCode}`);

        if (process.env.SMS_API_KEY) {
            try {
                const axios = require('axios');
                await axios.get('https://www.fast2sms.com/dev/bulkV2', {
                   params: {
                   route: 'dlt',
                   message: `Your OrderSync OTP is ${otpCode}. Valid for 10 minutes.`,
                   language: 'english',
                   flash: 0,
                   numbers: identifier
                },
                headers: {
                  'authorization': process.env.SMS_API_KEY,
                  'accept': 'application/json'
                }
            });
                console.log(`📱 SMS Sent successfully to ${identifier}`);
            } catch (smsErr) {
                console.error('❌ Fast2SMS Actual Error:', smsErr.response?.data || smsErr.message);
                console.warn('⚠️ SMS Gateway Warning (falling back to dev response)');
            }
        }
        
        res.json({ 
            success: true, 
            message: "OTP sent successfully.",
            dev_otp: otpCode // টেস্টিং ও ইনস্ট্যান্ট ভেরিফিকেশনের জন্য
        });
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

// ================= PUBLIC PLANS API =================
app.get('/api/public/plans', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM subscription_plans ORDER BY price ASC");
        res.json({ success: true, plans: result.rows });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch public plans" });
    }
});

// ================= SUBSCRIPTION & SUPER ADMIN APIS =================
app.post('/api/restaurant/register', async (req, res) => {
    try {
        const { id, name, phone, email } = req.body;
        if (!id || !name || !phone || !email) {
            return res.status(400).json({ error: "All fields are required." });
        }
        const trialExpiresAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);

        await pool.query(
            `INSERT INTO restaurants (id, name, phone, email, assigned_plan, subscription_status, plan_expires_at) 
             VALUES ($1, $2, $3, $4, 'Free Trial', 'ACTIVE', $5)
             ON CONFLICT (id) DO UPDATE SET 
             assigned_plan = EXCLUDED.assigned_plan, 
             subscription_status = EXCLUDED.subscription_status, 
             plan_expires_at = EXCLUDED.plan_expires_at`,
            [id, name, phone, email, trialExpiresAt]
        );

        res.json({ 
            success: true, 
            message: "Restaurant registered with 14 days free trial!",
            plan_expires_at: trialExpiresAt
        });
    } catch (err) {
        console.error("Registration Error:", err);
        res.status(500).json({ error: "Registration failed." });
    }
});

app.post('/api/admin/update-subscription', async (req, res) => {
    try {
        const { admin_secret, restaurant_id, assigned_plan, plan_expires_at, subscription_status } = req.body;
        if (admin_secret !== process.env.SUPER_ADMIN_SECRET) {
            return res.status(403).json({ error: "Unauthorized Super Admin Action!" });
        }

        await pool.query(
            `UPDATE restaurants 
             SET assigned_plan = COALESCE($1, assigned_plan), 
                 plan_expires_at = COALESCE($2, plan_expires_at), 
                 subscription_status = COALESCE($3, subscription_status) 
             WHERE id = $4`,
            [assigned_plan, plan_expires_at, subscription_status, restaurant_id]
        );

        res.json({ 
            success: true, 
            message: `Subscription updated for restaurant ID: ${restaurant_id}` 
        });
    } catch (err) {
        console.error("Admin Update Error:", err);
        res.status(500).json({ error: "Failed to update subscription." });
    }
});

app.get('/api/admin/plans', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM subscription_plans ORDER BY price ASC");
        res.json({ success: true, plans: result.rows });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch plans" });
    }
});

app.post('/api/admin/plans', async (req, res) => {
    try {
        const { admin_secret, plan_name, price, duration_days, max_staff, description } = req.body;
        if (admin_secret !== process.env.SUPER_ADMIN_SECRET) {
            return res.status(403).json({ error: "Unauthorized" });
        }
        await pool.query(
            `INSERT INTO subscription_plans (plan_name, price, duration_days, max_staff, description)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (plan_name) DO UPDATE SET price = EXCLUDED.price, duration_days = EXCLUDED.duration_days, max_staff = EXCLUDED.max_staff, description = EXCLUDED.description`,
            [plan_name, price, duration_days, max_staff, description]
        );
        res.json({ success: true, message: "Subscription plan saved/updated successfully!" });
    } catch (err) {
        console.error("Plan Save Error:", err);
        res.status(500).json({ error: "Failed to save plan" });
    }
});

const verifySuperAdmin = (req, res, next) => {
    const adminSecret = req.headers['x-admin-secret'] || req.body.admin_secret;
    if (!adminSecret || adminSecret !== process.env.SUPER_ADMIN_SECRET) {
        return res.status(403).json({ error: "Access Denied: Invalid Super Admin Secret!" });
    }
    next();
};

app.get('/api/admin/stats', verifySuperAdmin, async (req, res) => {
    try {
        const totalRestaurants = await pool.query("SELECT COUNT(*) FROM restaurants");
        const activeSubscriptions = await pool.query("SELECT COUNT(*) FROM restaurants WHERE subscription_status = 'ACTIVE' AND plan_expires_at > NOW()");
        res.json({
            success: true,
            stats: {
                total_restaurants: parseInt(totalRestaurants.rows[0].count),
                active_subscriptions: parseInt(activeSubscriptions.rows[0].count)
            }
        });
    } catch (err) {
        console.error("Stats Error:", err);
        res.status(500).json({ error: "Failed to fetch admin stats." });
    }
});

app.get('/api/admin/restaurants', verifySuperAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, name, phone, email, subscription_status, assigned_plan, plan_expires_at, created_at 
             FROM restaurants 
             ORDER BY created_at DESC`
        );
        res.json({ success: true, restaurants: result.rows });
    } catch (err) {
        console.error("Fetch Restaurants Error:", err);
        res.status(500).json({ error: "Failed to fetch restaurants." });
    }
});

app.post('/api/admin/restaurant-status', verifySuperAdmin, async (req, res) => {
    try {
        const { restaurant_id, status } = req.body; 
        if (!restaurant_id || !status) {
            return res.status(400).json({ error: "Restaurant ID and status are required." });
        }
        await pool.query(
            "UPDATE restaurants SET subscription_status = $1 WHERE id = $2",
            [status, restaurant_id]
        );
        res.json({ success: true, message: `Restaurant ${restaurant_id} status updated to ${status}` });
    } catch (err) {
        console.error("Status Update Error:", err);
        res.status(500).json({ error: "Failed to update restaurant status." });
    }
});

// ================= AUTHENTICATION LOGIN & REGISTER =================
app.post('/api/auth/register', async (req, res) => {
    const restaurantName = req.body.restaurantName?.trim();
    const phone = req.body.phone?.trim();
    const email = req.body.email?.trim().toLowerCase();
    const password = req.body.password;

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
        const trialExpiresAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);

        await client.query(
            `INSERT INTO restaurants (id, name, phone, email, subscription_status, assigned_plan, plan_expires_at)
             VALUES ($1, $2, $3, $4, 'ACTIVE', 'Free Trial', $5)`,
            [restaurantId, restaurantName, phone, email, trialExpiresAt]
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
        res.status(201).json({ success: true, token, restaurantId, message: "Registration successful with 14-day trial!" });
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

// ================= KITCHEN MODULE APIS (Protected with Subscription Guard) =================
app.get('/api/kitchen/orders/:restaurantId', verifySubscription, async (req, res) => {
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

app.patch('/api/kitchen/order-status', verifySubscription, async (req, res) => {
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

// ================= ADMIN MODULE APIS (Protected with Subscription Guard where applicable) =================
app.get('/api/admin/menu/:restaurantId', verifySubscription, async (req, res) => {
    try {
        const { restaurantId } = req.params;
        const result = await pool.query("SELECT * FROM menu_items WHERE restaurant_id = $1 ORDER BY id DESC", [restaurantId]);
        res.json({ success: true, menu: result.rows });
    } catch (err) {
        console.error("❌ Admin Menu Fetch Error:", err.message);
        res.status(500).json({ error: "Failed to fetch admin menu." });
    }
});

app.post('/api/admin/menu', verifySubscription, async (req, res) => {
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
        const queryRes = await pool.query(
            `UPDATE menu_items SET name = COALESCE($1, name), category = COALESCE($2, category), 
             price = COALESCE($3, price), available = COALESCE($4, available) WHERE id = $5 RETURNING *`,
            [name, category, price, available, itemId]
        );
        res.json({ success: true, item: queryRes.rows[0] });
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

app.get('/api/admin/stats/:restaurantId', verifySubscription, async (req, res) => {
    try {
        const { restaurantId } = req.params;
        const salesRes = await pool.query("SELECT COALESCE(SUM(grand_total), 0) as total_sales FROM sales_invoices WHERE restaurant_id = $1", [restaurantId]);
        const ordersRes = await pool.query("SELECT COUNT(*) as total_orders FROM orders WHERE restaurant_id = $1", [restaurantId]);
        res.json({
            success: true,
            totalSales: parseFloat(salesRes.rows[0].total_sales || 0),
            totalOrders: parseInt(ordersRes.rows[0].total_orders || 0)
        });
    } catch (err) {
        console.error("❌ Admin Stats Error:", err.message);
        res.status(500).json({ error: "Failed to fetch admin stats." });
    }
});

// ================= BILLING MODULE APIS (Protected with Subscription Guard) =================
app.get('/api/billing/orders/:restaurantId', verifySubscription, async (req, res) => {
    try {
        const { restaurantId } = req.params;
        const result = await pool.query("SELECT * FROM orders WHERE restaurant_id = $1 AND payment = 'Unpaid' ORDER BY created_at DESC", [restaurantId]);
        res.json({ success: true, orders: result.rows });
    } catch (err) {
        console.error("❌ Billing Orders Error:", err.message);
        res.status(500).json({ error: "Failed to fetch billing orders." });
    }
});

app.post('/api/billing/checkout', verifySubscription, async (req, res) => {
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

// ================= WAITER MODULE APIS (Protected with Subscription Guard) =================
app.post('/api/waiter/orders', verifySubscription, async (req, res) => {
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

if (process.env.REDIS_URL || process.env.USE_REDIS === 'true') {
    try {
        const { createClient } = require('redis');
        const { createAdapter } = require('@socket.io/redis-adapter');
        const pubClient = createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
        const subClient = pubClient.duplicate();

        Promise.all([pubClient.connect(), subClient.connect()]).then(() => {
            io.adapter(createAdapter(pubClient, subClient));
            console.log("⚡ Socket.io Redis Adapter Connected Successfully!");
        }).catch(err => {
            console.warn("⚠️ Redis Adapter Connection Failed, continuing with local socket.io:", err.message);
        });
    } catch (rErr) {
        console.warn("⚠️ Redis module/setup warning:", rErr.message);
    }
}

// ================= PRODUCTION ERROR MASKING MIDDLEWARE =================
app.use((err, req, res, next) => {
    console.error("🔒 Security Error Log:", err.message);
    res.status(500).json({ error: "Internal Security Error. Request blocked." });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`🚀 OrderTrack High-Scale Enterprise Server running on port ${PORT}`);
});