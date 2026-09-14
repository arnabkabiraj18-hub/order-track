-- =========================================================================
-- ORDERTRACK ENTERPRISE SAAS - FINAL PRODUCTION DATABASE SCHEMA
-- =========================================================================

-- 1. RESTAURANTS MASTER TABLE
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

-- 2. RESTAURANT STAFF & ADMIN USERS TABLE
CREATE TABLE IF NOT EXISTS restaurant_users (
    id SERIAL PRIMARY KEY,
    restaurant_id VARCHAR(64) REFERENCES restaurants(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) DEFAULT 'Manager',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. OTP VERIFICATION TABLE
CREATE TABLE IF NOT EXISTS phone_otps (
    identifier VARCHAR(255) PRIMARY KEY,
    otp_code VARCHAR(6) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. AUTHORIZED DEVICES & QUICK PIN LOGIN TABLE
CREATE TABLE IF NOT EXISTS authorized_devices (
    id SERIAL PRIMARY KEY,
    restaurant_id VARCHAR(64) REFERENCES restaurants(id) ON DELETE CASCADE,
    device_uuid VARCHAR(255) UNIQUE NOT NULL,
    device_name VARCHAR(100),
    quick_pin_hash VARCHAR(255),
    role VARCHAR(50) DEFAULT 'Staff',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. MENU ITEMS CATALOG TABLE
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

-- 6. REAL-TIME ORDERS & KDS QUEUE TABLE
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

-- 7. POS SALES INVOICES TABLE
CREATE TABLE IF NOT EXISTS sales_invoices (
    id SERIAL PRIMARY KEY,
    restaurant_id VARCHAR(64) REFERENCES restaurants(id) ON DELETE CASCADE,
    invoice_no VARCHAR(100) UNIQUE NOT NULL,
    table_no VARCHAR(20),
    grand_total NUMERIC(10, 2) NOT NULL,
    payment_mode VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 8. SUPPORT TICKETS TABLE
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

-- =========================================================================
-- HIGH-PERFORMANCE INDEXING (Optimized for 100k+ Concurrent Restaurants)
-- =========================================================================
CREATE INDEX IF NOT EXISTS idx_restaurants_id ON restaurants(id);
CREATE INDEX IF NOT EXISTS idx_restaurants_phone ON restaurants(phone);
CREATE INDEX IF NOT EXISTS idx_users_email ON restaurant_users(email);
CREATE INDEX IF NOT EXISTS idx_users_phone ON restaurant_users(phone);
CREATE INDEX IF NOT EXISTS idx_devices_uuid ON authorized_devices(device_uuid);
CREATE INDEX IF NOT EXISTS idx_orders_resto ON orders(restaurant_id);