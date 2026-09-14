module.exports = {
  apps: [
    {
      name: "ordertrack-enterprise",
      script: "./server.js",
      instances: "max", // কম্পিউটারের বা ক্লাউড সার্ভারের সবকটি CPU কোর ব্যবহার করবে
      exec_mode: "cluster", // ক্লাস্টার মোড এনাবল করবে
      env: {
        NODE_ENV: "production",
      },
      env_development: {
        NODE_ENV: "development",
      },
      max_memory_restart: '500M', // কোনো মেমোরি লিক হলে অটো রিস্টার্ট নেবে
      autorestart: true,
      watch: false
    },
  ],
};