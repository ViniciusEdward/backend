const path = require('path');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');

const envPath = process.env.NODE_ENV === 'test' ? path.join(__dirname, '..', '.env.test') : path.join(__dirname, '..', '.env');
dotenv.config({ path: envPath });

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT || 3306),
    waitForConnections: true,
    connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
    queueLimit: Number(process.env.DB_QUEUE_LIMIT || 0),
    enableKeepAlive: true,
    keepAliveInitialDelay: 0,
    decimalNumbers: true,
    timezone: 'Z',
    multipleStatements: false
});

module.exports = pool;



