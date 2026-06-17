// Escapar HTML para evitar XSS
const escapeHtml = (unsafe) => {
    if (typeof unsafe !== 'string') return '';
    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
};

// Sanitizar objeto de entrada
const sanitizeObject = (obj) => {
    if (!obj || typeof obj !== 'object') return {};
    const sanitized = {};
    
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
            sanitized[key] = escapeHtml(value.trim()).substring(0, 255);
        } else if (typeof value === 'number') {
            sanitized[key] = value;
        } else if (typeof value === 'boolean') {
            sanitized[key] = value;
        }
    }
    
    return sanitized;
};

module.exports = { escapeHtml, sanitizeObject };



