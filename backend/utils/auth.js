const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Gerar hash de senha
const hashPassword = async (senha) => {
    const salt = await bcrypt.genSalt(12);
    return bcrypt.hash(senha, salt);
};

// Comparar senha com hash
const comparePassword = async (senha, hash) => {
    return bcrypt.compare(senha, hash);
};

// Gerar JWT token
const generateToken = (user) => {
    return jwt.sign(
        { 
            idusuario: user.idusuario, 
            email: user.email,
            primeironome: user.primeironome 
        },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRE || '7d' }
    );
};

module.exports = { hashPassword, comparePassword, generateToken };



