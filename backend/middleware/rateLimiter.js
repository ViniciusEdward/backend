const rateLimit = require('express-rate-limit');

const isTest = process.env.NODE_ENV === 'test' || process.env.TEST_MODE === '1';

const loginLimiter = rateLimit({
    windowMs: isTest ? 5 * 1000 : 15 * 60 * 1000,
    max: isTest ? 1000 : 5,
    message: isTest ? 'Rate limiter (test mode) active' : 'Muitas tentativas de login. Tente novamente em 15 minutos.',
    standardHeaders: true,
    legacyHeaders: false,
});

const apiLimiter = rateLimit({
    windowMs: isTest ? 1000 : 60 * 1000,
    max: isTest ? 10000 : 100,
    message: 'Muitas requisições. Tente novamente depois.',
});

module.exports = { loginLimiter, apiLimiter };



