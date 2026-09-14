const API_BASE_URL = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.hostname.startsWith('192.168.'))
    ? `http://${window.location.hostname}:5000/api` // লোকাল নেটওয়ার্কে থাকলে অটো সেই আইপি ও পোর্টে কাজ করবে
    : 'https://your-live-backend-domain.com/api'; // পুরোপুরি লাইভে চলে গেলে এই ব্যাকএন্ড ডোমেইন ধরবে

export const api = {
    // কমন ফেচ হ্যান্ডলার (টোেকেন সহ)
    async request(endpoint, options = {}) {
        const token = localStorage.getItem('token');
        const headers = {
            'Content-Type': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
            ...options.headers
        };

        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                ...options,
                headers
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'Server request failed!');
            }
            return data;
        } catch (err) {
            console.error("API Request Error:", err.message);
            throw err;
        }
    },

    // ১. ওটিপি পাঠানো
    sendOtp(identifier) {
        return this.request('/auth/send-otp', {
            method: 'POST',
            body: JSON.stringify({ identifier })
        });
    },

    // ২. ওটিপি ভেরিফাই করা
    verifyOtp(identifier, otpCode) {
        return this.request('/auth/verify-otp', {
            method: 'POST',
            body: JSON.stringify({ identifier, otpCode })
        });
    },

    // ৩. রেস্টুরেন্ট রেজিস্ট্রেশন
    async register(restaurantData) {
        const data = await this.request('/auth/register', {
            method: 'POST',
            body: JSON.stringify(restaurantData)
        });
        if (data.success && data.token) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('restaurantId', data.restaurantId);
        }
        return data;
    },

    // ৪. লগইন
    async login(identifier, password) {
        const data = await this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ identifier, password })
        });
        if (data.success && data.token) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('restaurantId', data.restaurantId);
        }
        return data;
    },

    // ৫. মেনু ফেচ করা (পাবলিক / কাস্টমার)
    getMenu(restaurantId) {
        return this.request(`/public/menu/${restaurantId}`);
    },

    // ৬. অর্ডার প্লেস করা (পাবলিক / কাস্টমার)
    placeOrder(orderData) {
        return this.request('/public/orders', {
            method: 'POST',
            body: JSON.stringify(orderData)
        });
    },

    // ==========================================
    // ৭. কিচেন মডিউল (Kitchen Module)
    // ==========================================
    getKitchenOrders(restaurantId) {
        return this.request(`/kitchen/orders/${restaurantId}`);
    },

    updateOrderStatus(orderId, status) {
        return this.request('/kitchen/order-status', {
            method: 'PATCH',
            body: JSON.stringify({ orderId, status })
        });
    },

    // ==========================================
    // ৮. অ্যাডমিন মডিউল (Admin Module)
    // ==========================================
    getAdminMenu(restaurantId) {
        return this.request(`/admin/menu/${restaurantId}`);
    },

    addMenuItem(itemData) {
        return this.request('/admin/menu', {
            method: 'POST',
            body: JSON.stringify(itemData)
        });
    },

    updateMenuItem(itemId, itemData) {
        return this.request(`/admin/menu/${itemId}`, {
            method: 'PUT',
            body: JSON.stringify(itemData)
        });
    },

    deleteMenuItem(itemId) {
        return this.request(`/admin/menu/${itemId}`, {
            method: 'DELETE'
        });
    },

    getAdminStats(restaurantId) {
        return this.request(`/admin/stats/${restaurantId}`);
    },

    // ==========================================
    // ৯. বিলিং মডিউল (Billing / Cashier Module)
    // ==========================================
    getBillingOrders(restaurantId) {
        return this.request(`/billing/orders/${restaurantId}`);
    },

    processPayment(paymentData) {
        return this.request('/billing/checkout', {
            method: 'POST',
            body: JSON.stringify(paymentData)
        });
    },

    // ==========================================
    // ১০. ওয়েটার মডিউল (Waiter Module)
    // ==========================================
    createWaiterOrder(orderData) {
        return this.request('/waiter/orders', {
            method: 'POST',
            body: JSON.stringify(orderData)
        });
    }
};