const validator = {
    // Valida email
    isValidEmail: (email) => {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email) && email.length <= 150;
    },

    // Valida senha (mínimo 8 caracteres)
    isValidPassword: (senha) => {
        return typeof senha === 'string' && senha.length >= 8 && senha.length <= 255;
    },

    // Valida nome
    isValidName: (name) => {
        return typeof name === 'string' && name.trim().length > 0 && name.length <= 50;
    },

    isValidTitle: (title) => {
        return typeof title === 'string' && title.trim().length >= 2 && title.trim().length <= 150;
    },

    isValidDescription: (description) => {
        return typeof description === 'string' && description.trim().length <= 2000;
    },

    isValidQueueLimit: (limit) => {
        const parsed = Number(limit);
        return Number.isInteger(parsed) && parsed >= 1 && parsed <= 15;
    },

    isValidDeadlineDays: (days) => {
        const parsed = Number(days);
        return Number.isInteger(parsed) && parsed >= 1 && parsed <= 15;
    },

    isValidImageUrl: (url) => {
        if (url === undefined || url === null || url === '') return true;
        if (typeof url !== 'string') return false;
        const value = url.trim();
        if (!value) return true;

        // Upload local persistido pelo backend.
        if (value.startsWith('/uploads/items/')) {
            return !value.includes('..') && /^\/uploads\/items\/[a-z0-9._-]+\.(jpe?g|png|webp)$/i.test(value);
        }

        // Upload recebido do frontend como data URL temporária. O backend grava o arquivo e armazena /uploads/...
        if (/^data:image\/(jpeg|jpg|png|webp);base64,[a-z0-9+/=\s]+$/i.test(value)) {
            // Mantém a requisição abaixo de ~5 MB de arquivo bruto.
            return value.length <= 7_000_000;
        }

        // Mantém compatibilidade com imagens antigas por URL externa, mas bloqueia protocolos inseguros.
        if (value.length > 2048 || /[<>"'`]/.test(value)) return false;
        try {
            const parsed = new URL(value);
            return ['http:', 'https:'].includes(parsed.protocol);
        } catch (error) {
            return false;
        }
    },

    // Valida telefone simples
    isValidPhone: (phone) => {
        const digits = typeof phone === 'string' ? phone.replace(/\D/g, '') : '';
        return /^\d{8,9}$/.test(digits);
    },

    // Valida DDD
    isValidDDD: (ddd) => {
        return typeof ddd === 'string' && /^\d{2}$/.test(ddd);
    },

    // Valida CPF (aceita com ou sem máscara)
    isValidCPF: (cpf) => {
        if (typeof cpf !== 'string') return false;
        const digits = cpf.replace(/\D/g, '');
        return /^\d{11}$/.test(digits);
    },

    // Valida localização
    isValidCoordinates: (lat, lon) => {
        const latitude = parseFloat(lat);
        const longitude = parseFloat(lon);
        return !isNaN(latitude) && !isNaN(longitude) && 
               latitude >= -90 && latitude <= 90 && 
               longitude >= -180 && longitude <= 180;
    },

    isValidState: (state) => {
        if (typeof state !== 'string') return false;
        const trimmed = state.trim();
        if (/^[A-Za-z]{2}$/.test(trimmed)) return true;
        const normalized = trimmed.toLowerCase();
        const states = {
            'acre': 'ac', 'alagoas': 'al', 'amapa': 'ap', 'amazonas': 'am', 'bahia': 'ba',
            'ceara': 'ce', 'distrito federal': 'df', 'espirito santo': 'es', 'goias': 'go',
            'maranhao': 'ma', 'mato grosso': 'mt', 'mato grosso do sul': 'ms', 'minas gerais': 'mg',
            'para': 'pa', 'paraiba': 'pb', 'parana': 'pr', 'pernambuco': 'pe', 'piaui': 'pi',
            'rio de janeiro': 'rj', 'rio grande do norte': 'rn', 'rio grande do sul': 'rs',
            'rondonia': 'ro', 'roraima': 'rr', 'santa catarina': 'sc', 'sao paulo': 'sp',
            'sergipe': 'se', 'tocantins': 'to'
        };
        return Object.prototype.hasOwnProperty.call(states, normalized);
    },

    isValidCity: (city) => {
        return typeof city === 'string' && city.trim().length > 0 && city.trim().length <= 50;
    },

    isValidStreet: (street) => {
        return typeof street === 'string' && street.trim().length > 0 && street.trim().length <= 100;
    },

    isValidNeighborhood: (neighborhood) => {
        return typeof neighborhood === 'string' && neighborhood.trim().length <= 50;
    },

    isValidNumber: (num) => {
        return typeof num === 'string' && num.trim().length > 0 && num.trim().length <= 4;
    },

    isValidMessage: (message) => {
        return typeof message === 'string' && message.trim().length > 0 && message.trim().length <= 500;
    },

    isValidComment: (comment) => {
        return comment === undefined || comment === null ||
            (typeof comment === 'string' && comment.trim().length <= 1000);
    },

    isValidRating: (rating) => {
        const parsed = Number(rating);
        return Number.isInteger(parsed) && parsed >= 1 && parsed <= 5;
    },

    // Limpa strings perigosas
    sanitizeString: (str) => {
        if (typeof str !== 'string') return '';
        return str.trim().substring(0, 255);
    },

    // Valida número ID
    isValidID: (id) => {
        const parsed = Number(id);
        return Number.isInteger(parsed) && parsed > 0;
    }
};

module.exports = validator;



