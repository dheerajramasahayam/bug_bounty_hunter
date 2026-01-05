
module.exports = {
    apps: [
        {
            name: "bughunter-monitor",
            script: "./dist/cli/index.js",
            args: "daemon --aggressive --monitor-interval 1 --discovery-interval 2",
            instances: 1,
            autorestart: true,
            watch: false,
            max_memory_restart: "1G",
            env: {
                NODE_ENV: "production",
            },
        },
        {
            name: "bughunter-dashboard",
            script: "./dist/dashboard/server.js",
            instances: 1,
            autorestart: true,
            watch: false,
            env: {
                NODE_ENV: "production",
                PORT: 3000,
                DASHBOARD_HOST: "0.0.0.0"
            },
        }
    ],
};
