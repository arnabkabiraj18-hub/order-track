const CACHE_NAME = 'ordertrack-cache-v2';
const ASSETS_TO_CACHE = [
    '/',
    '/index.html',
    '/admin.html'
];

// Install Event: স্কিপ ওয়েটিং এবং ফাইলগুলো ক্যাশ করে রাখা
self.addEventListener('install', (e) => {
    self.skipWaiting();
    e.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(ASSETS_TO_CACHE);
        }).catch(err => console.log('Cache install error:', err))
    );
});

// Activate Event: ক্লায়েন্ট কন্ট্রোল নেওয়া এবং পুরোনো ক্যাশ ক্লিন করা
self.addEventListener('activate', (e) => {
    self.clients.claim();
    e.waitUntil(
        caches.keys().then((keyList) => {
            return Promise.all(keyList.map((key) => {
                if (key !== CACHE_NAME) {
                    return caches.delete(key);
                }
            }));
        })
    );
});

// Fetch Event: ইন্টারনেট থাকলে লাইভ ডেটা আনবে, স্লো বা অফলাইন থাকলে ক্যাশ থেকে দেখাবে
self.addEventListener('fetch', (e) => {
    e.respondWith(
        fetch(e.request)
            .then((res) => {
                return res;
            })
            .catch(() => {
                return caches.match(e.request);
            })
    );
});