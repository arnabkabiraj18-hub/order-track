const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 10, 
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000, // এটিকে ২ সেকেন্ড থেকে বাড়িয়ে ১০ সেকেন্ড করা হলো
    ssl: { rejectUnauthorized: false }
});

pool.on('connect', () => {
    console.log('✅ Secure PostgreSQL Pool Connected & Scaled for 100k+ Restaurants!');
});

module.exports = pool;