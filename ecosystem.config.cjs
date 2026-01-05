module.exports = {
    apps: [
        {
            name: 'bughunter-daemon',
            script: 'dist/cli/index.js',
            args: 'daemon',
            interpreter: 'node',
            cwd: __dirname,
            instances: 1,
            autorestart: true,
            watch: false,
            max_memory_restart: '1G',
            env: {
                NODE_ENV: 'production',
            },
            env_production: {
                NODE_ENV: 'production',
            },
            // Restart at midnight daily to clear memory
            cron_restart: '0 0 * * *',
            // Wait 30 seconds before restarting on crash
            restart_delay: 30000,
            // Max 10 restarts in 15 minutes
            max_restarts: 10,
            min_uptime: '1m',
            // Log configuration
            out_file: './logs/pm2-out.log',
            error_file: './logs/pm2-error.log',
            merge_logs: true,
            log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
        },
        {
            name: 'bughunter-dashboard',
            script: 'dist/dashboard/server.js',
            interpreter: 'node',
            cwd: __dirname,
            instances: 1,
            autorestart: true,
            watch: false,
            env: {
                NODE_ENV: 'production',
                PORT: 3000,
                DASHBOARD_HOST: '0.0.0.0',
            },
            out_file: './logs/dashboard-out.log',
            error_file: './logs/dashboard-error.log',
            merge_logs: true,
            log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
        },
    ],
};
