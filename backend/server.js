const path = require('path');
const dotenv = require('dotenv');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');

const isTest = process.env.NODE_ENV === 'test' || process.env.TEST_MODE === '1';
const envPath = isTest ? path.join(__dirname, '.env.test') : path.join(__dirname, '.env');
dotenv.config({ path: envPath });

const app = express();

const requiredEnv = ['JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
const missingEnv = requiredEnv.filter((name) => process.env[name] === undefined);
if (missingEnv.length > 0) {
    const message = `Missing required environment variable(s): ${missingEnv.join(', ')}`;
    if (!isTest) {
        console.error(message);
        process.exit(1);
    }
    console.warn(message);
}

const isProduction = process.env.NODE_ENV === 'production';
if (!isTest && process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    console.error('JWT_SECRET must have at least 32 characters.');
    process.exit(1);
}

// Importações de módulos de segurança
const authMiddleware = require('./middleware/authMiddleware');
const { loginLimiter, apiLimiter } = require('./middleware/rateLimiter');
const validator = require('./utils/validator');
const { escapeHtml, sanitizeObject } = require('./utils/sanitizer');
const { hashPassword, comparePassword, generateToken } = require('./utils/auth');
const { calcularDistancia } = require('./utils/distance');
const pool = require('./config/database');

// In-memory store para tokens de recuperação (apenas para testes locais)
const passwordResetTokens = new Map();

const normalizeString = (value) => typeof value === 'string' ? value.trim() : '';
const brazilStateMap = {
    'acre': 'AC', 'alagoas': 'AL', 'amapa': 'AP', 'amazonas': 'AM', 'bahia': 'BA',
    'ceara': 'CE', 'distrito federal': 'DF', 'espirito santo': 'ES', 'goias': 'GO',
    'maranhao': 'MA', 'mato grosso': 'MT', 'mato grosso do sul': 'MS', 'minas gerais': 'MG',
    'para': 'PA', 'paraiba': 'PB', 'parana': 'PR', 'pernambuco': 'PE', 'piaui': 'PI',
    'rio de janeiro': 'RJ', 'rio grande do norte': 'RN', 'rio grande do sul': 'RS',
    'rondonia': 'RO', 'roraima': 'RR', 'santa catarina': 'SC', 'sao paulo': 'SP',
    'sergipe': 'SE', 'tocantins': 'TO'
};
const normalizeState = (value) => {
    const state = normalizeString(value);
    if (!state) return '';
    if (/^[A-Za-z]{2}$/.test(state)) {
        return state.toUpperCase();
    }
    return brazilStateMap[state.toLowerCase()] || state.toUpperCase();
};
const normalizePhone = (value) => typeof value === 'string' ? value.replace(/\D/g, '') : '';
const clampInteger = (value, fallback, min, max) => {
    const parsed = Number.parseInt(value, 10);
    if (Number.isNaN(parsed)) return fallback;
    return Math.min(Math.max(parsed, min), max);
};
const tableColumnExists = async (connection, tableName, columnName) => {
    const [columns] = await connection.query(`SHOW COLUMNS FROM \`${tableName}\` LIKE ?`, [columnName]);
    return columns.length > 0;
};
const getItemSchemaSupport = async (connection) => ({
    hasPrazoDias: await tableColumnExists(connection, 'item', 'prazo_dias'),
    hasDtCriacao: await tableColumnExists(connection, 'item', 'dtcriacao'),
    hasDataDoacao: await tableColumnExists(connection, 'item', 'datadoacao'),
    hasLimiteFila: await tableColumnExists(connection, 'item', 'limite_fila'),
    hasImagemUrl: await tableColumnExists(connection, 'item', 'imagem_url'),
    hasStatus: await tableColumnExists(connection, 'item', 'status')
});
const getUserSchemaSupport = async (connection) => ({
    hasFotoUrl: await tableColumnExists(connection, 'usuario', 'foto_url'),
    hasImagemUrl: await tableColumnExists(connection, 'usuario', 'imagem_url'),
    hasTotalDoacoes: await tableColumnExists(connection, 'usuario', 'total_doacoes')
});
const getMessageSchemaSupport = async (connection) => ({
    hasDtMensagen: await tableColumnExists(connection, 'mensagem', 'dtmensagen'),
    hasDtMensagem: await tableColumnExists(connection, 'mensagem', 'dtmensagem'),
    hasLida: await tableColumnExists(connection, 'mensagem', 'lida')
});
const getItemDateExpression = ({ hasDtCriacao, hasDataDoacao }) => {
    if (hasDtCriacao && hasDataDoacao) return 'COALESCE(i.dtcriacao, i.datadoacao)';
    if (hasDtCriacao) return 'i.dtcriacao';
    return 'i.datadoacao';
};
const getItemQueueLimitExpression = ({ hasLimiteFila }) => hasLimiteFila ? 'COALESCE(i.limite_fila, 10)' : '10';
const getItemImageExpression = ({ hasImagemUrl }) => hasImagemUrl ? 'i.imagem_url' : 'NULL';
const getUserPhotoExpression = ({ hasFotoUrl, hasImagemUrl }) => {
    if (hasFotoUrl) return 'u.foto_url';
    if (hasImagemUrl) return 'u.imagem_url';
    return 'NULL';
};
const getMessageDateColumn = ({ hasDtMensagen, hasDtMensagem }) => {
    if (hasDtMensagen) return 'dtmensagen';
    if (hasDtMensagem) return 'dtmensagem';
    return null;
};
const getItemStatusExpression = ({ hasStatus }) => {
    if (hasStatus) return 'COALESCE(i.status, \'disponivel\')';
    return `CASE
        WHEN EXISTS (
            SELECT 1 FROM solicitacao s_status
            WHERE s_status.item_iditem = i.iditem AND s_status.status = 'entregue'
        ) THEN 'finalizada'
        WHEN EXISTS (
            SELECT 1 FROM solicitacao s_status
            WHERE s_status.item_iditem = i.iditem
              AND s_status.status IN ('aceito', 'reservado', 'aguardando_entrega', 'em_processo')
        ) THEN 'reservada'
        ELSE 'disponivel'
    END`;
};
const getPublicItemFilter = ({ hasStatus }) => {
    const statusFilter = hasStatus ? "AND COALESCE(i.status, 'disponivel') = 'disponivel'" : '';
    return `
        ${statusFilter}
        AND NOT EXISTS (
            SELECT 1 FROM solicitacao s_public
            WHERE s_public.item_iditem = i.iditem
              AND s_public.status IN ('aceito', 'reservado', 'entregue', 'aguardando_entrega', 'em_processo')
        )
    `;
};
const ACCEPTED_STATUSES = ['aceito', 'reservado', 'aguardando_entrega', 'em_processo'];
// Permite chat assim que existe uma solicitação entre doador e interessado.
// Antes 'pendente' ficava fora e o frontend recebia 403 ao abrir/enviar chat depois de solicitar.
const ACTIVE_CHAT_STATUSES = ['pendente', 'aceito', 'reservado', 'aguardando_entrega', 'em_processo', 'entregue'];
const AUTO_ACCEPT_MESSAGE = 'Sua solicitação foi aceita. Utilize este chat para combinar a retirada da doação.';
const EVALUATION_TYPES = {
    DONOR_RATES_BENEFICIARY: 'doador_avalia_beneficiario',
    BENEFICIARY_RATES_DONOR_ITEM: 'beneficiario_avalia_doador_item'
};

const tableIndexExists = async (connection, tableName, indexName) => {
    const [indexes] = await connection.query(`SHOW INDEX FROM \`${tableName}\` WHERE Key_name = ?`, [indexName]);
    return indexes.length > 0;
};

const ensureAvaliacaoSchema = async (connection) => {
    const addColumnIfMissing = async (columnName, definition) => {
        if (!(await tableColumnExists(connection, 'avaliacao', columnName))) {
            await connection.query(`ALTER TABLE avaliacao ADD COLUMN ${definition}`);
        }
    };

    await addColumnIfMissing('idsolicitacao', 'idsolicitacao INT NULL');
    await addColumnIfMissing('iditem', 'iditem INT NULL');
    await addColumnIfMissing('tipo_avaliacao', `tipo_avaliacao ENUM('${EVALUATION_TYPES.DONOR_RATES_BENEFICIARY}', '${EVALUATION_TYPES.BENEFICIARY_RATES_DONOR_ITEM}') DEFAULT '${EVALUATION_TYPES.BENEFICIARY_RATES_DONOR_ITEM}'`);
    await addColumnIfMissing('ocorreu_tudo_bem', 'ocorreu_tudo_bem BOOLEAN DEFAULT NULL');
    await addColumnIfMissing('encontrou_pessoa', 'encontrou_pessoa BOOLEAN DEFAULT NULL');
    await addColumnIfMissing('item_conforme', 'item_conforme BOOLEAN DEFAULT NULL');
    await addColumnIfMissing('sem_problemas', 'sem_problemas BOOLEAN DEFAULT NULL');
    await addColumnIfMissing('imagem_feedback_url', 'imagem_feedback_url VARCHAR(2048) DEFAULT NULL');

    if (await tableIndexExists(connection, 'avaliacao', 'unique_avaliacao')) {
        await connection.query('ALTER TABLE avaliacao DROP INDEX unique_avaliacao');
    }
    if (!(await tableIndexExists(connection, 'avaliacao', 'idx_avaliacao_solicitacao'))) {
        await connection.query('CREATE INDEX idx_avaliacao_solicitacao ON avaliacao (idsolicitacao)');
    }
    if (!(await tableIndexExists(connection, 'avaliacao', 'idx_avaliacao_item'))) {
        await connection.query('CREATE INDEX idx_avaliacao_item ON avaliacao (iditem)');
    }
    if (!(await tableIndexExists(connection, 'avaliacao', 'unique_avaliacao_solicitacao_tipo'))) {
        await connection.query('CREATE UNIQUE INDEX unique_avaliacao_solicitacao_tipo ON avaliacao (idsolicitacao, tipo_avaliacao, idusuario_avaliador)');
    }
};

const toBooleanOrNull = (value) => {
    if (value === null || value === undefined || value === '') return null;
    return value === true || value === 'true' || value === 1 || value === '1';
};

const normalizeItemPayload = (body = {}) => {
    const titulo = normalizeString(body.titulo || body.title);
    const descricao = typeof body.descricao === 'string' ? body.descricao.trim() : '';
    const latitude = Number.parseFloat(body.latitude);
    const longitude = Number.parseFloat(body.longitude);
    const limiteFila = clampInteger(body.limiteFila ?? body.limite_fila, 10, 1, 15);
    const prazoDias = clampInteger(body.prazo_dias ?? body.prazoDias, 7, 1, 15);
    const imagemUrl = normalizeString(body.imagem_url || body.imagemUrl || '');

    return {
        titulo,
        descricao,
        latitude,
        longitude,
        limite_fila: limiteFila,
        prazo_dias: prazoDias,
        imagem_url: imagemUrl
    };
};

const calculateQueueCandidates = (item, candidatos) => candidatos
    .map((candidato) => ({
        ...candidato,
        distancia_km: calcularDistancia(
            Number(item.latitude),
            Number(item.longitude),
            Number(candidato.latitude),
            Number(candidato.longitude)
        )
    }))
    .sort((a, b) => {
        if (a.distancia_km !== b.distancia_km) return a.distancia_km - b.distancia_km;
        return new Date(a.datarequisicao) - new Date(b.datarequisicao);
    });

const insertChatMessage = async (connection, remetenteId, destinatarioId, conteudo) => {
    const messageSchema = await getMessageSchemaSupport(connection);
    const dateColumn = getMessageDateColumn(messageSchema);
    const columns = ['usuario_idusuario', 'usuario_idusuario1', 'conteudo'];
    const values = ['?', '?', '?'];
    const params = [remetenteId, destinatarioId, escapeHtml(String(conteudo).trim())];

    if (dateColumn) {
        columns.push(`\`${dateColumn}\``);
        values.push('NOW()');
    }
    if (messageSchema.hasLida) {
        columns.push('lida');
        values.push('FALSE');
    }

    const [result] = await connection.query(
        `INSERT INTO mensagem (${columns.join(', ')}) VALUES (${values.join(', ')})`,
        params
    );
    return result.insertId;
};

const usersHaveExistingMessages = async (connection, userAId, userBId) => {
    const [rows] = await connection.query(`
        SELECT 1
        FROM mensagem
        WHERE (
            (usuario_idusuario = ? AND usuario_idusuario1 = ?)
            OR (usuario_idusuario = ? AND usuario_idusuario1 = ?)
        )
        LIMIT 1
    `, [userAId, userBId, userBId, userAId]);
    return rows.length > 0;
};

const usersHaveDonationRelationship = async (connection, userAId, userBId, statuses = ACTIVE_CHAT_STATUSES) => {
    const placeholders = statuses.map(() => '?').join(', ');
    const [rows] = await connection.query(`
        SELECT 1
        FROM solicitacao s
        JOIN item i ON s.item_iditem = i.iditem
        WHERE s.status IN (${placeholders})
          AND (
            (i.usuario_idusuario = ? AND s.usuario_idusuario = ?)
            OR (i.usuario_idusuario = ? AND s.usuario_idusuario = ?)
          )
        LIMIT 1
    `, [...statuses, userAId, userBId, userBId, userAId]);
    return rows.length > 0;
};

const canUsersChat = async (connection, userAId, userBId) => {
    if (Number(userAId) === Number(userBId)) return false;
    if (await usersHaveDonationRelationship(connection, userAId, userBId)) return true;
    return usersHaveExistingMessages(connection, userAId, userBId);
};

const markItemStatus = async (connection, iditem, status) => {
    const itemSchema = await getItemSchemaSupport(connection);
    if (itemSchema.hasStatus) {
        await connection.query('UPDATE item SET status = ? WHERE iditem = ?', [status, iditem]);
    }
};

const incrementDonorStats = async (connection, doadorId) => {
    const userSchema = await getUserSchemaSupport(connection);
    if (userSchema.hasTotalDoacoes) {
        await connection.query('UPDATE usuario SET total_doacoes = COALESCE(total_doacoes, 0) + 1 WHERE idusuario = ?', [doadorId]);
    }
};

const registerItemProcessing = async (connection, iditem) => {
    await connection.query(
        'INSERT INTO item_processamento (iditem) VALUES (?) ON DUPLICATE KEY UPDATE processado_em = NOW()',
        [iditem]
    );
};

const acceptSolicitation = async (connection, solicitacao, doadorId) => {
    const idsolicitacao = Number(solicitacao.idsolicitacao);
    const iditem = Number(solicitacao.item_iditem);
    const beneficiarioId = Number(solicitacao.beneficiario || solicitacao.usuario_idusuario);

    const [updateResult] = await connection.query(
        "UPDATE solicitacao SET status = 'aguardando_entrega' WHERE idsolicitacao = ? AND status = 'pendente'",
        [idsolicitacao]
    );

    if (updateResult.affectedRows === 0) {
        const [current] = await connection.query('SELECT status FROM solicitacao WHERE idsolicitacao = ?', [idsolicitacao]);
        const currentStatus = current[0]?.status;
        if (!ACCEPTED_STATUSES.includes(currentStatus)) {
            const error = new Error('Solicitação não está pendente');
            error.statusCode = 409;
            throw error;
        }
    }

    await connection.query(
        "UPDATE solicitacao SET status = 'cancelado' WHERE item_iditem = ? AND idsolicitacao != ? AND status = 'pendente'",
        [iditem, idsolicitacao]
    );
    await markItemStatus(connection, iditem, 'reservada');
    await registerItemProcessing(connection, iditem);
    await insertChatMessage(connection, doadorId, beneficiarioId, AUTO_ACCEPT_MESSAGE);

    return { iditem, beneficiarioId, idsolicitacao };
};

const finalizeAcceptedDonation = async (connection, item, solicitacao) => {
    const iditem = Number(item.iditem);
    const doadorId = Number(item.usuario_idusuario);
    const idsolicitacao = Number(solicitacao.idsolicitacao);
    const beneficiarioId = Number(solicitacao.usuario_idusuario);

    await connection.query(
        "UPDATE solicitacao SET status = 'entregue' WHERE idsolicitacao = ? AND status IN ('aceito', 'reservado', 'aguardando_entrega', 'em_processo')",
        [idsolicitacao]
    );
    await markItemStatus(connection, iditem, 'finalizada');
    await registerItemProcessing(connection, iditem);
    await incrementDonorStats(connection, doadorId);

    return { iditem, doadorId, beneficiarioId, idsolicitacao };
};

const runFinalizeItemFlow = async (connection, iditem, usuarioId) => {
    const itemSchema = await getItemSchemaSupport(connection);
    const statusExpr = getItemStatusExpression(itemSchema);

    const [itemRows] = await connection.query(
        `SELECT iditem, usuario_idusuario, latitude, longitude, ${statusExpr} AS status FROM item i WHERE iditem = ?`,
        [iditem]
    );

    if (itemRows.length === 0) {
        const error = new Error('Item não encontrado');
        error.statusCode = 404;
        throw error;
    }
    if (Number(itemRows[0].usuario_idusuario) !== Number(usuarioId)) {
        const error = new Error('Acesso negado');
        error.statusCode = 403;
        throw error;
    }

    await connection.beginTransaction();
    try {
        const [acceptedRows] = await connection.query(`
            SELECT idsolicitacao, item_iditem, usuario_idusuario
            FROM solicitacao
            WHERE item_iditem = ? AND status IN ('aceito', 'reservado', 'aguardando_entrega', 'em_processo')
            ORDER BY datarequisicao ASC
            LIMIT 1
        `, [iditem]);

        if (acceptedRows.length > 0) {
            const finalizada = await finalizeAcceptedDonation(connection, itemRows[0], acceptedRows[0]);
            await connection.commit();
            return {
                sucesso: true,
                status: 'finalizada',
                iditem: finalizada.iditem,
                idsolicitacao: finalizada.idsolicitacao,
                idusuario_beneficiario: finalizada.beneficiarioId,
                idusuario_vencedor: finalizada.beneficiarioId
            };
        }

        if (itemRows[0].status === 'finalizada') {
            const error = new Error('Doação já finalizada');
            error.statusCode = 409;
            throw error;
        }

        const [candidatosRows] = await connection.query(`
            SELECT s.idsolicitacao, s.item_iditem, s.usuario_idusuario AS beneficiario,
                s.datarequisicao, u.latitude, u.longitude
            FROM solicitacao s
            JOIN usuario u ON s.usuario_idusuario = u.idusuario
            WHERE s.item_iditem = ? AND s.status = 'pendente'
        `, [iditem]);

        const candidatos = calculateQueueCandidates(itemRows[0], candidatosRows);
        if (candidatos.length === 0) {
            const error = new Error('Não há interessados na fila');
            error.statusCode = 400;
            throw error;
        }

        const aceita = await acceptSolicitation(connection, candidatos[0], usuarioId);
        await connection.commit();
        return {
            sucesso: true,
            status: 'reservada',
            iditem: aceita.iditem,
            idsolicitacao: aceita.idsolicitacao,
            idusuario_vencedor: aceita.beneficiarioId
        };
    } catch (error) {
        await connection.rollback();
        throw error;
    }
};

const cleanupExpiredPasswordResetTokens = () => {
    const now = Date.now();
    for (const [token, record] of passwordResetTokens.entries()) {
        if (!record || record.expires < now) {
            passwordResetTokens.delete(token);
        }
    }
};

// ============= MIDDLEWARE DE SEGURANÇA =============
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", 'https://unpkg.com', 'https://cdnjs.cloudflare.com'],
            styleSrc: ["'self'", 'https://unpkg.com', 'https://cdnjs.cloudflare.com', 'https://fonts.googleapis.com', "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:', 'https:', 'https://unpkg.com', 'https://*.tile.openstreetmap.org', 'https://*.openstreetmap.fr', 'https://*.openstreetmap.de'],
            connectSrc: ["'self'", 'https://unpkg.com', 'https://nominatim.openstreetmap.org', 'https://*.tile.openstreetmap.org', 'https://*.openstreetmap.fr', 'https://*.openstreetmap.de', 'https://backend-1z9z.onrender.com', 'https://*.vercel.app'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
            objectSrc: ["'none'"],
            frameAncestors: ["'self'"]
        }
    }
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// CORS restritivo
const defaultAllowedOrigins = isProduction ? [] : [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://127.0.0.1:5500',
    'http://localhost:5500'
];
const envAllowedOrigins = process.env.CORS_ORIGIN?.split(',').map(origin => origin.trim()).filter(Boolean) || [];
const allowedOrigins = Array.from(new Set([...defaultAllowedOrigins, ...envAllowedOrigins]));
console.log('✓ Allowed CORS origins:', allowedOrigins);

app.use(cors({
    origin: (origin, callback) => {
        const requestedOrigin = typeof origin === 'string' ? origin.trim() : origin;
        const isLocalhostOrigin = !isProduction && typeof requestedOrigin === 'string' && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(requestedOrigin);

        // Permite requests sem origin (ex: ferramentas de teste ou servidores de mesmo host)
        if (!requestedOrigin || allowedOrigins.includes(requestedOrigin) || isLocalhostOrigin) {
            return callback(null, true);
        }

        callback(new Error(`CORS policy: origin ${origin} not allowed`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting global
app.use('/api/', apiLimiter);

const fs = require('fs');
const uploadsRoot = path.join(__dirname, '..', 'uploads');
const itemUploadsDir = path.join(uploadsRoot, 'items');
const feedbackUploadsDir = path.join(uploadsRoot, 'feedback');
fs.mkdirSync(itemUploadsDir, { recursive: true });
fs.mkdirSync(feedbackUploadsDir, { recursive: true });

app.use('/uploads', express.static(uploadsRoot, {
    index: false,
    fallthrough: false,
    maxAge: isProduction ? '7d' : 0,
    setHeaders: (res) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
    }
}));

const frontendCandidates = [
    path.join(__dirname, '..', 'frontend_github'),
    path.join(__dirname, '..', 'frontend', 'public')
];
const frontendPath = frontendCandidates.find(candidate => fs.existsSync(candidate));
if (frontendPath) {
    app.use(express.static(frontendPath));
}

const IMAGE_MIME_EXTENSION = {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp'
};

const parseDataImage = (value = '') => {
    if (typeof value !== 'string') return null;
    const match = value.trim().match(/^data:(image\/(?:jpeg|jpg|png|webp));base64,([a-z0-9+/=\s]+)$/i);
    if (!match) return null;
    const mime = match[1].toLowerCase() === 'image/jpg' ? 'image/jpeg' : match[1].toLowerCase();
    const buffer = Buffer.from(match[2].replace(/\s/g, ''), 'base64');
    if (!buffer.length || buffer.length > 5 * 1024 * 1024) return null;

    const signature = buffer.subarray(0, 12).toString('hex');
    const isJpeg = mime === 'image/jpeg' && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
    const isPng = mime === 'image/png' && signature.startsWith('89504e470d0a1a0a');
    const isWebp = mime === 'image/webp' && buffer.subarray(0, 4).toString('ascii') === 'RIFF' && buffer.subarray(8, 12).toString('ascii') === 'WEBP';
    if (!isJpeg && !isPng && !isWebp) return null;

    return { mime, buffer, extension: IMAGE_MIME_EXTENSION[mime] };
};

const persistItemImage = async (imageValue = '') => {
    const value = normalizeString(imageValue);
    if (!value) return '';
    if (value.startsWith('/uploads/items/')) return value;
    if (/^https?:\/\//i.test(value)) return value;

    const parsed = parseDataImage(value);
    if (!parsed) {
        const error = new Error('Imagem inválida. Use JPG, PNG ou WebP de até 5 MB.');
        error.statusCode = 400;
        throw error;
    }

    const filename = `${Date.now()}-${crypto.randomBytes(12).toString('hex')}.${parsed.extension}`;
    const filepath = path.join(itemUploadsDir, filename);
    await fs.promises.writeFile(filepath, parsed.buffer, { flag: 'wx', mode: 0o644 });
    return `/uploads/items/${filename}`;
};

const persistFeedbackImage = async (imageValue = '') => {
    const value = normalizeString(imageValue);
    if (!value) return '';
    if (value.startsWith('/uploads/feedback/')) {
        if (!/^\/uploads\/feedback\/[a-z0-9._-]+\.(jpe?g|png|webp)$/i.test(value) || value.includes('..')) {
            const error = new Error('Imagem de feedback inválida.');
            error.statusCode = 400;
            throw error;
        }
        return value;
    }

    const parsed = parseDataImage(value);
    if (!parsed) {
        const error = new Error('Imagem de feedback inválida. Use JPG, PNG ou WebP de até 5 MB.');
        error.statusCode = 400;
        throw error;
    }

    const filename = `${Date.now()}-${crypto.randomBytes(12).toString('hex')}.${parsed.extension}`;
    const filepath = path.join(feedbackUploadsDir, filename);
    await fs.promises.writeFile(filepath, parsed.buffer, { flag: 'wx', mode: 0o644 });
    return `/uploads/feedback/${filename}`;
};

// ============= TRATAMENTO DE ERROS =============
const handleError = (res, statusCode, message, error = null) => {
    console.error(message, error);
    const response = { erro: message };
    if (process.env.NODE_ENV !== 'production' && error) {
        response.debug = error.stack || error.message;
    }
    res.status(statusCode).json(response);
};

// ============= ROTAS PÚBLICAS =============

// Login
app.post('/api/login', isTest ? (req, res, next) => next() : loginLimiter, async (req, res) => {
    let connection;
    try {
        const { email, senha } = req.body;

        // Validação rigorosa
        if (!validator.isValidEmail(email) || !validator.isValidPassword(senha)) {
            return res.status(400).json({ erro: 'Email ou senha inválidos' });
        }

        connection = await pool.getConnection();
        const [rows] = await connection.query(
            'SELECT idusuario, email, senha, primeironome, sobrenome FROM usuario WHERE email = ?',
            [email]
        );

        if (rows.length === 0) {
            return res.status(401).json({ erro: 'Email ou senha incorretos' });
        }

        const user = rows[0];
        const isPasswordValid = await comparePassword(senha, user.senha);

        if (!isPasswordValid) {
            return res.status(401).json({ erro: 'Email ou senha incorretos' });
        }

        const token = generateToken(user);
        res.json({
            sucesso: true,
            token,
            usuario: {
                idusuario: user.idusuario,
                email: user.email,
                primeironome: user.primeironome,
                sobrenome: user.sobrenome
            }
        });
    } catch (error) {
        handleError(res, 500, 'Erro ao fazer login', error);
    } finally {
        if (connection) connection.release();
    }
});

// Registro
app.post('/api/usuarios', async (req, res) => {
    let connection;
    try {
        // Extrair senha ANTES de sanitizar para evitar corrupção por escapeHtml
        const senhaRaw = typeof req.body?.senha === 'string' ? req.body.senha : '';
        const body = sanitizeObject(req.body || {});
        const {
            primeironome = '',
            sobrenome = '',
            cpf = '',
            ddd = '',
            telefone = '',
            email = '',
            estado = '',
            cidade = '',
            bairro = '',
            logradouro = '',
            numero = '',
            latitude,
            longitude
        } = body;
        const senha = senhaRaw;

        // Validações rigorosas
        const validationResults = {
            nome: validator.isValidName(primeironome),
            sobrenome: validator.isValidName(sobrenome),
            cpf: validator.isValidCPF(cpf),
            ddd: validator.isValidDDD(ddd),
            telefone: validator.isValidPhone(telefone),
            email: validator.isValidEmail(email),
            senha: validator.isValidPassword(senha),
            estado: validator.isValidState(estado),
            cidade: validator.isValidCity(cidade),
            logradouro: validator.isValidStreet(logradouro),
            numero: validator.isValidNumber(numero),
            bairro: validator.isValidNeighborhood(bairro),
            coordenadas: validator.isValidCoordinates(latitude, longitude)
        };

        if (Object.values(validationResults).includes(false)) {
            return res.status(400).json({ erro: 'Dados de registro inválidos' });
        }

        // Limpar dados
        const userData = {
            primeironome: escapeHtml(normalizeString(primeironome)),
            sobrenome: escapeHtml(normalizeString(sobrenome)),
            cpf: normalizePhone(cpf),
            ddd: normalizeString(ddd),
            telefone: normalizePhone(telefone),
            email: normalizeString(email).toLowerCase(),
            estado: normalizeState(estado),
            cidade: escapeHtml(normalizeString(cidade)),
            bairro: escapeHtml(normalizeString(bairro)),
            logradouro: escapeHtml(normalizeString(logradouro)),
            numero: escapeHtml(normalizeString(numero)),
            latitude: parseFloat(latitude),
            longitude: parseFloat(longitude)
        };

        // Verificar duplicação
        connection = await pool.getConnection();
        const [existing] = await connection.query(
            'SELECT idusuario FROM usuario WHERE email = ? OR cpf = ?',
            [userData.email, userData.cpf]
        );

        if (existing.length > 0) {
            return res.status(400).json({ erro: 'Email ou CPF já cadastrado' });
        }

        // Hash da senha
        const senhaHash = await hashPassword(senha);

        // Inserir usuário
        const [result] = await connection.query(
            'INSERT INTO usuario (primeironome, sobrenome, cpf, ddd, telefone, email, logradouro, bairro, numero, cidade, estado, latitude, longitude, senha) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [userData.primeironome, userData.sobrenome, userData.cpf, userData.ddd, userData.telefone, userData.email, userData.logradouro, userData.bairro, userData.numero, userData.cidade, userData.estado, userData.latitude, userData.longitude, senhaHash]
        );

        const newUser = { idusuario: result.insertId, email: userData.email, primeironome: userData.primeironome, sobrenome: userData.sobrenome };
        const token = generateToken(newUser);

        res.status(201).json({
            sucesso: true,
            token,
            usuario: newUser
        });
    } catch (error) {
        handleError(res, 500, 'Erro ao registrar usuário', error);
    } finally {
        if (connection) connection.release();
    }
});

// ============= ROTAS PROTEGIDAS =============

// Listar itens (com distância calculada e ordenação por proximidade)
app.get('/api/itens', authMiddleware, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();

        let userLat = parseFloat(req.query.lat);
        let userLon = parseFloat(req.query.lon);

        if (!validator.isValidCoordinates(userLat, userLon)) {
            const [userRows] = await connection.query(
                'SELECT latitude, longitude FROM usuario WHERE idusuario = ?',
                [req.user.idusuario]
            );

            if (userRows.length === 0) {
                return res.status(404).json({ erro: 'Usuário não encontrado' });
            }

            userLat = userRows[0].latitude;
            userLon = userRows[0].longitude;
        }

        const itemSchema = await getItemSchemaSupport(connection);
        const dateExpr = getItemDateExpression(itemSchema);
        const intervalExpr = itemSchema.hasPrazoDias ? 'i.prazo_dias' : '7';
        const queueLimitExpr = getItemQueueLimitExpression(itemSchema);
        const imageExpr = getItemImageExpression(itemSchema);
        const statusExpr = getItemStatusExpression(itemSchema);
        const publicFilter = getPublicItemFilter(itemSchema);

        const [itens] = await connection.query(`
            SELECT 
                i.iditem,
                i.titulo,
                i.descricao,
                i.latitude,
                i.longitude,
                i.usuario_idusuario,
                ${queueLimitExpr} AS limite_fila,
                ${imageExpr} AS imagem_url,
                ${statusExpr} AS status,
                u.primeironome,
                ${dateExpr} AS dtcriacao,
                DATEDIFF(DATE_ADD(${dateExpr}, INTERVAL ${intervalExpr} DAY), NOW()) AS dias_restantes,
                (SELECT COUNT(*) FROM solicitacao s2 WHERE s2.item_iditem = i.iditem AND s2.status = 'pendente') AS total_na_fila,
                (SELECT s_user.status FROM solicitacao s_user WHERE s_user.item_iditem = i.iditem AND s_user.usuario_idusuario = ? ORDER BY s_user.datarequisicao DESC LIMIT 1) AS minha_solicitacao_status
            FROM item i
            JOIN usuario u ON i.usuario_idusuario = u.idusuario
            WHERE i.usuario_idusuario != ?
              ${publicFilter}
        `, [req.user.idusuario, req.user.idusuario]);

        const itensComDistancia = itens
            .map(item => ({
                ...item,
                status: item.status || 'disponivel',
                distancia: Number(calcularDistancia(userLat, userLon, item.latitude, item.longitude).toFixed(2)),
                dias_restantes: Math.max(0, Number(item.dias_restantes)),
                total_na_fila: Number(item.total_na_fila || 0),
                limite_fila: Number(item.limite_fila || 10)
            }))
            .sort((a, b) => a.distancia - b.distancia);

        res.json(itensComDistancia);
    } catch (error) {
        handleError(res, 500, 'Erro ao listar itens', error);
    } finally {
        if (connection) connection.release();
    }
});

// Criar item de doação
app.post('/api/itens', authMiddleware, async (req, res) => {
    let connection;
    try {
        const itemData = normalizeItemPayload(req.body);

        if (!validator.isValidTitle(itemData.titulo) ||
            !validator.isValidDescription(itemData.descricao) ||
            !validator.isValidCoordinates(itemData.latitude, itemData.longitude) ||
            !validator.isValidQueueLimit(itemData.limite_fila) ||
            !validator.isValidDeadlineDays(itemData.prazo_dias) ||
            !validator.isValidImageUrl(itemData.imagem_url)) {
            return res.status(400).json({ erro: 'Dados de item inválidos' });
        }

        connection = await pool.getConnection();
        const [userRows] = await connection.query(
            'SELECT idusuario FROM usuario WHERE idusuario = ?',
            [req.user.idusuario]
        );

        if (userRows.length === 0) {
            return res.status(404).json({ erro: 'Usuário não encontrado' });
        }

        const itemSchema = await getItemSchemaSupport(connection);
        const persistedImagePath = await persistItemImage(itemData.imagem_url);
        const columns = ['titulo', 'descricao'];
        const values = ['?', '?'];
        const insertParams = [escapeHtml(itemData.titulo), escapeHtml(itemData.descricao)];

        if (itemSchema.hasDtCriacao) {
            columns.push('dtcriacao');
            values.push('NOW()');
        }
        if (itemSchema.hasDataDoacao) {
            columns.push('datadoacao');
            values.push('NOW()');
        }

        columns.push('latitude', 'longitude', 'usuario_idusuario');
        values.push('?', '?', '?');
        insertParams.push(itemData.latitude, itemData.longitude, req.user.idusuario);

        if (itemSchema.hasPrazoDias) {
            columns.push('prazo_dias');
            values.push('?');
            insertParams.push(itemData.prazo_dias);
        }
        if (itemSchema.hasLimiteFila) {
            columns.push('limite_fila');
            values.push('?');
            insertParams.push(itemData.limite_fila);
        }
        if (itemSchema.hasImagemUrl && persistedImagePath) {
            columns.push('imagem_url');
            values.push('?');
            insertParams.push(persistedImagePath);
        }
        if (itemSchema.hasStatus) {
            columns.push('status');
            values.push('?');
            insertParams.push('disponivel');
        }

        const insertSql = `INSERT INTO item (${columns.join(', ')}) VALUES (${values.join(', ')})`;

        const [result] = await connection.query(insertSql, insertParams);

        res.status(201).json({
            sucesso: true,
            iditem: result.insertId
        });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({ erro: error.message });
        }
        handleError(res, 500, 'Erro ao criar item', error);
    } finally {
        if (connection) connection.release();
    }
});

// Listar meus itens publicados
app.get('/api/itens/minhas', authMiddleware, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await ensureAvaliacaoSchema(connection);
        const itemSchema = await getItemSchemaSupport(connection);
        const dateExpr = getItemDateExpression(itemSchema);
        const queueLimitExpr = getItemQueueLimitExpression(itemSchema);
        const imageExpr = getItemImageExpression(itemSchema);
        const statusExpr = getItemStatusExpression(itemSchema);
        const [itens] = await connection.query(`
            SELECT 
                i.iditem,
                i.titulo,
                i.descricao,
                i.latitude,
                i.longitude,
                ${queueLimitExpr} AS limite_fila,
                ${imageExpr} AS imagem_url,
                ${statusExpr} AS status,
                ${dateExpr} AS dtcriacao,
                (SELECT COUNT(*) FROM solicitacao s2 WHERE s2.item_iditem = i.iditem AND s2.status = 'pendente') AS total_na_fila,
                (SELECT COUNT(*) FROM solicitacao s3 WHERE s3.item_iditem = i.iditem) AS total_solicitacoes,
                (
                    SELECT s4.idsolicitacao
                    FROM solicitacao s4
                    WHERE s4.item_iditem = i.iditem AND s4.status IN ('aceito', 'reservado', 'aguardando_entrega', 'em_processo', 'entregue')
                    ORDER BY s4.datarequisicao ASC
                    LIMIT 1
                ) AS idsolicitacao_aceita,
                (
                    SELECT s5.usuario_idusuario
                    FROM solicitacao s5
                    WHERE s5.item_iditem = i.iditem AND s5.status IN ('aceito', 'reservado', 'aguardando_entrega', 'em_processo', 'entregue')
                    ORDER BY s5.datarequisicao ASC
                    LIMIT 1
                ) AS beneficiario_id,
                (
                    SELECT u5.primeironome
                    FROM solicitacao s5
                    JOIN usuario u5 ON u5.idusuario = s5.usuario_idusuario
                    WHERE s5.item_iditem = i.iditem AND s5.status IN ('aceito', 'reservado', 'aguardando_entrega', 'em_processo', 'entregue')
                    ORDER BY s5.datarequisicao ASC
                    LIMIT 1
                ) AS beneficiario_nome,
                EXISTS(
                    SELECT 1
                    FROM avaliacao a
                    JOIN solicitacao s6 ON a.idsolicitacao = s6.idsolicitacao
                    WHERE s6.item_iditem = i.iditem
                      AND s6.status = 'entregue'
                      AND a.idusuario_avaliador = ?
                      AND a.tipo_avaliacao = ?
                    LIMIT 1
                ) AS avaliacao_enviada
            FROM item i
            WHERE i.usuario_idusuario = ?
            ORDER BY dtcriacao DESC
        `, [req.user.idusuario, EVALUATION_TYPES.DONOR_RATES_BENEFICIARY, req.user.idusuario]);
        res.json(itens);
    } catch (error) {
        handleError(res, 500, 'Erro ao listar meus itens', error);
    } finally {
        if (connection) connection.release();
    }
});

// Detalhar item
app.get('/api/itens/:iditem', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { iditem } = req.params;
        if (!validator.isValidID(iditem)) {
            return res.status(400).json({ erro: 'ID do item inválido' });
        }

        connection = await pool.getConnection();
        const itemSchema = await getItemSchemaSupport(connection);
        const dateExpr = getItemDateExpression(itemSchema);
        const queueLimitExpr = getItemQueueLimitExpression(itemSchema);
        const imageExpr = getItemImageExpression(itemSchema);
        const statusExpr = getItemStatusExpression(itemSchema);
        const [rows] = await connection.query(`
            SELECT
                i.iditem,
                i.titulo,
                i.descricao,
                i.latitude,
                i.longitude,
                i.usuario_idusuario,
                ${queueLimitExpr} AS limite_fila,
                ${imageExpr} AS imagem_url,
                ${statusExpr} AS status,
                ${dateExpr} AS dtcriacao,
                u.primeironome,
                (SELECT COUNT(*) FROM solicitacao s2 WHERE s2.item_iditem = i.iditem AND s2.status = 'pendente') AS total_na_fila,
                (SELECT s_user.status FROM solicitacao s_user WHERE s_user.item_iditem = i.iditem AND s_user.usuario_idusuario = ? ORDER BY s_user.datarequisicao DESC LIMIT 1) AS minha_solicitacao_status,
                (
                    SELECT s_acc.usuario_idusuario
                    FROM solicitacao s_acc
                    WHERE s_acc.item_iditem = i.iditem AND s_acc.status IN ('aceito', 'reservado', 'aguardando_entrega', 'em_processo', 'entregue')
                    ORDER BY s_acc.datarequisicao ASC
                    LIMIT 1
                ) AS beneficiario_id,
                (
                    SELECT s_acc.idsolicitacao
                    FROM solicitacao s_acc
                    WHERE s_acc.item_iditem = i.iditem AND s_acc.status IN ('aceito', 'reservado', 'aguardando_entrega', 'em_processo', 'entregue')
                    ORDER BY s_acc.datarequisicao ASC
                    LIMIT 1
                ) AS idsolicitacao_aceita
            FROM item i
            JOIN usuario u ON i.usuario_idusuario = u.idusuario
            WHERE i.iditem = ?
        `, [req.user.idusuario, iditem]);

        if (rows.length === 0) {
            return res.status(404).json({ erro: 'Item não encontrado' });
        }

        const item = rows[0];
        const usuarioId = Number(req.user.idusuario);
        const doadorId = Number(item.usuario_idusuario);
        const beneficiarioId = Number(item.beneficiario_id);
        const itemReservadoOuFinalizado = ['reservada', 'finalizada'].includes(item.status);

        if (itemReservadoOuFinalizado && usuarioId !== doadorId && usuarioId !== beneficiarioId) {
            return res.status(403).json({ erro: 'Você não tem acesso a esta doação' });
        }

        res.json({
            ...item,
            total_na_fila: Number(item.total_na_fila || 0),
            limite_fila: Number(item.limite_fila || 10)
        });
    } catch (error) {
        handleError(res, 500, 'Erro ao carregar item', error);
    } finally {
        if (connection) connection.release();
    }
});

// Atualizar item de doação
app.put('/api/itens/:iditem', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { iditem } = req.params;
        if (!validator.isValidID(iditem)) {
            return res.status(400).json({ erro: 'ID do item inválido' });
        }

        const itemData = normalizeItemPayload(req.body);
        if (!validator.isValidTitle(itemData.titulo) ||
            !validator.isValidDescription(itemData.descricao) ||
            !validator.isValidCoordinates(itemData.latitude, itemData.longitude) ||
            !validator.isValidQueueLimit(itemData.limite_fila) ||
            !validator.isValidDeadlineDays(itemData.prazo_dias) ||
            !validator.isValidImageUrl(itemData.imagem_url)) {
            return res.status(400).json({ erro: 'Dados de item inválidos' });
        }

        connection = await pool.getConnection();
        const itemSchema = await getItemSchemaSupport(connection);
        const statusExpr = getItemStatusExpression(itemSchema);
        const [itemRows] = await connection.query(
            `SELECT usuario_idusuario, ${statusExpr} AS status FROM item i WHERE iditem = ?`,
            [iditem]
        );

        if (itemRows.length === 0) {
            return res.status(404).json({ erro: 'Item não encontrado' });
        }
        if (Number(itemRows[0].usuario_idusuario) !== Number(req.user.idusuario)) {
            return res.status(403).json({ erro: 'Você não tem permissão para editar este item' });
        }

        if (['reservada', 'finalizada'].includes(itemRows[0].status)) {
            return res.status(409).json({ erro: 'Não é possível editar um item reservado ou finalizado' });
        }

        const [blocked] = await connection.query(
            "SELECT 1 FROM solicitacao WHERE item_iditem = ? AND status IN ('aguardando_entrega', 'aceito', 'reservado', 'em_processo', 'entregue') LIMIT 1",
            [iditem]
        );
        if (blocked.length > 0) {
            return res.status(409).json({ erro: 'Não é possível editar um item reservado ou entregue' });
        }

        const persistedImagePath = await persistItemImage(itemData.imagem_url);
        const assignments = ['titulo = ?', 'descricao = ?', 'latitude = ?', 'longitude = ?'];
        const params = [
            escapeHtml(itemData.titulo),
            escapeHtml(itemData.descricao),
            itemData.latitude,
            itemData.longitude
        ];

        if (itemSchema.hasPrazoDias) {
            assignments.push('prazo_dias = ?');
            params.push(itemData.prazo_dias);
        }
        if (itemSchema.hasLimiteFila) {
            assignments.push('limite_fila = ?');
            params.push(itemData.limite_fila);
        }
        if (itemSchema.hasImagemUrl) {
            assignments.push('imagem_url = ?');
            params.push(persistedImagePath || null);
        }

        params.push(iditem);
        await connection.query(`UPDATE item SET ${assignments.join(', ')} WHERE iditem = ?`, params);
        res.json({ sucesso: true });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({ erro: error.message });
        }
        handleError(res, 500, 'Erro ao atualizar item', error);
    } finally {
        if (connection) connection.release();
    }
});

// Excluir item de doação
app.delete('/api/itens/:iditem', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { iditem } = req.params;
        if (!validator.isValidID(iditem)) {
            return res.status(400).json({ erro: 'ID do item inválido' });
        }

        connection = await pool.getConnection();
        const [itemRows] = await connection.query(
            'SELECT usuario_idusuario FROM item WHERE iditem = ?',
            [iditem]
        );

        if (itemRows.length === 0) {
            return res.status(404).json({ erro: 'Item não encontrado' });
        }
        if (Number(itemRows[0].usuario_idusuario) !== Number(req.user.idusuario)) {
            return res.status(403).json({ erro: 'Você não tem permissão para excluir este item' });
        }

        await connection.query('DELETE FROM item WHERE iditem = ?', [iditem]);
        res.json({ sucesso: true });
    } catch (error) {
        handleError(res, 500, 'Erro ao excluir item', error);
    } finally {
        if (connection) connection.release();
    }
});

// Solicitar doação
app.post('/api/solicita', authMiddleware, async (req, res) => {
    let connection;
    try {
        const iditem = req.body?.iditem ?? req.body?.item_iditem ?? req.body?.id_item ?? req.body?.id;

        if (!validator.isValidID(iditem)) {
            return res.status(400).json({ erro: 'ID do item inválido' });
        }

        connection = await pool.getConnection();
        const itemSchema = await getItemSchemaSupport(connection);
        const queueLimitExpr = getItemQueueLimitExpression(itemSchema);
        const statusExpr = getItemStatusExpression(itemSchema);

        // Verificar item
        const [itens] = await connection.query(
            `SELECT usuario_idusuario, ${queueLimitExpr} AS limite_fila, ${statusExpr} AS status FROM item i WHERE iditem = ?`,
            [iditem]
        );

        if (itens.length === 0) {
            return res.status(404).json({ erro: 'Item não encontrado' });
        }

        if (Number(itens[0].usuario_idusuario) === Number(req.user.idusuario)) {
            return res.status(400).json({ erro: 'Você não pode solicitar sua própria doação' });
        }

        if (itens[0].status !== 'disponivel') {
            return res.status(409).json({ erro: 'Este item não está mais disponível para solicitação.' });
        }

        // Verificar se já existe item aceito ou entregue
        const [itemStatus] = await connection.query(
            "SELECT 1 FROM solicitacao WHERE item_iditem = ? AND status IN ('aceito', 'reservado', 'aguardando_entrega', 'em_processo', 'entregue') LIMIT 1",
            [iditem]
        );

        if (itemStatus.length > 0) {
            return res.status(409).json({ erro: 'Este item já foi reservado ou entregue.' });
        }

        const [count] = await connection.query(
            "SELECT COUNT(*) as total FROM solicitacao WHERE item_iditem = ? AND status = 'pendente'",
            [iditem]
        );

        const limiteFila = Number(itens[0].limite_fila || 10);
        if (count[0].total >= limiteFila) {
            return res.status(409).json({ erro: `Fila cheia. Este item já tem ${limiteFila} solicitações pendentes.` });
        }

        // Verificar solicitação existente (por constraint unique do banco)
        // Se existir uma solicitação cancelada, permite re-solicitar via UPDATE
        // Se existir uma solicitação pendente/ativa, bloqueia
        const [existing] = await connection.query(
            'SELECT idsolicitacao, status FROM solicitacao WHERE item_iditem = ? AND usuario_idusuario = ? LIMIT 1',
            [iditem, req.user.idusuario]
        );

        let idsolicitacao;

        if (existing.length > 0) {
            if (existing[0].status !== 'cancelado') {
                return res.status(200).json({
                    sucesso: true,
                    jaSolicitado: true,
                    idsolicitacao: existing[0].idsolicitacao,
                    status: existing[0].status,
                    mensagem: 'Você já solicitou este item'
                });
            }
            // Row cancelada: reutilizar via UPDATE para contornar a UNIQUE constraint
            await connection.query(
                'UPDATE solicitacao SET status = \'pendente\', datarequisicao = NOW() WHERE idsolicitacao = ?',
                [existing[0].idsolicitacao]
            );
            idsolicitacao = existing[0].idsolicitacao;
        } else {
            // Criar nova solicitação
            const [result] = await connection.query(
                'INSERT INTO solicitacao (item_iditem, usuario_idusuario, datarequisicao, status) VALUES (?, ?, NOW(), "pendente")',
                [iditem, req.user.idusuario]
            );
            idsolicitacao = result.insertId;
        }

        res.status(existing.length > 0 ? 200 : 201).json({
            sucesso: true,
            idsolicitacao
        });
    } catch (error) {
        handleError(res, 500, 'Erro ao solicitar doação', error);
    } finally {
        if (connection) connection.release();
    }
});

// Listar solicitações de usuário
app.get('/api/solicitacoes', authMiddleware, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [solicitacoes] = await connection.query(`
            SELECT 
                s.idsolicitacao,
                s.item_iditem AS iditem,
                s.datarequisicao,
                s.status,
                i.titulo,
                u.primeironome
            FROM solicitacao s
            JOIN item i ON s.item_iditem = i.iditem
            JOIN usuario u ON i.usuario_idusuario = u.idusuario
            WHERE s.usuario_idusuario = ?
            ORDER BY s.datarequisicao DESC
        `, [req.user.idusuario]);
        
        res.json(solicitacoes);
    } catch (error) {
        handleError(res, 500, 'Erro ao listar solicitações', error);
    } finally {
        if (connection) connection.release();
    }
});

// Posição do usuário na fila de um item
app.get('/api/itens/:iditem/fila', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { iditem } = req.params;

        if (!validator.isValidID(iditem)) {
            return res.status(400).json({ erro: 'ID do item inválido' });
        }

        connection = await pool.getConnection();
        const itemSchema = await getItemSchemaSupport(connection);
        const dateExpr = getItemDateExpression(itemSchema);
        const intervalExpr = itemSchema.hasPrazoDias ? 'i.prazo_dias' : '7';
        const [itemRows] = await connection.query(`
            SELECT i.iditem, i.latitude, i.longitude,
                DATEDIFF(DATE_ADD(${dateExpr}, INTERVAL ${intervalExpr} DAY), NOW()) AS dias_restantes
            FROM item i
            WHERE i.iditem = ?
        `, [iditem]);

        if (itemRows.length === 0) {
            return res.status(404).json({ erro: 'Item não encontrado' });
        }

        const [candidatos] = await connection.query(`
            SELECT s.idsolicitacao, s.usuario_idusuario, s.datarequisicao, u.latitude, u.longitude
            FROM solicitacao s
            JOIN usuario u ON s.usuario_idusuario = u.idusuario
            WHERE s.item_iditem = ? AND s.status = 'pendente'
        `, [iditem]);

        const filaOrdenada = calculateQueueCandidates(itemRows[0], candidatos);
        const positionIndex = filaOrdenada.findIndex((row) => Number(row.usuario_idusuario) === Number(req.user.idusuario));

        if (positionIndex === -1) {
            return res.status(404).json({ erro: 'Fila não encontrada para este item ou você não está na fila' });
        }

        const fila = filaOrdenada[positionIndex];
        res.json({
            posicao: positionIndex + 1,
            total: filaOrdenada.length,
            distancia_km: Number(fila.distancia_km.toFixed(2)),
            dias_restantes: Math.max(0, Number(itemRows[0].dias_restantes))
        });
    } catch (error) {
        handleError(res, 500, 'Erro ao consultar posição na fila', error);
    } finally {
        if (connection) connection.release();
    }
});

// Fila detalhada para o doador
app.get('/api/itens/:iditem/fila-detalhada', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { iditem } = req.params;
        if (!validator.isValidID(iditem)) {
            return res.status(400).json({ erro: 'ID do item inválido' });
        }

        connection = await pool.getConnection();

        const [itemRows] = await connection.query(
            'SELECT usuario_idusuario, latitude, longitude FROM item WHERE iditem = ?',
            [iditem]
        );

        if (itemRows.length === 0) {
            return res.status(404).json({ erro: 'Item não encontrado' });
        }
        if (Number(itemRows[0].usuario_idusuario) !== Number(req.user.idusuario)) {
            return res.status(403).json({ erro: 'Acesso negado' });
        }

        const userSchema = await getUserSchemaSupport(connection);
        const photoExpr = getUserPhotoExpression(userSchema);
        const [fila] = await connection.query(`
            SELECT
                u.idusuario,
                u.primeironome,
                u.sobrenome,
                ${photoExpr} AS foto_url,
                u.latitude,
                u.longitude,
                s.idsolicitacao,
                s.datarequisicao,
                s.status
            FROM solicitacao s
            JOIN usuario u ON s.usuario_idusuario = u.idusuario
            WHERE s.item_iditem = ? AND s.status = 'pendente'
        `, [iditem]);

        const filaOrdenada = calculateQueueCandidates(itemRows[0], fila).map((row, index) => ({
            idusuario: row.idusuario,
            primeironome: row.primeironome,
            sobrenome: row.sobrenome,
            foto_url: row.foto_url,
            idsolicitacao: row.idsolicitacao,
            datarequisicao: row.datarequisicao,
            status: row.status,
            posicao: index + 1,
            distancia_km: Number(row.distancia_km.toFixed(2))
        }));

        res.json(filaOrdenada);
    } catch (error) {
        handleError(res, 500, 'Erro ao carregar fila detalhada', error);
    } finally {
        if (connection) connection.release();
    }
});


// Fila completa para modal em tempo real no feed e nas telas do item
app.get('/api/itens/:iditem/fila-completa', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { iditem } = req.params;
        if (!validator.isValidID(iditem)) {
            return res.status(400).json({ erro: 'ID do item inválido' });
        }

        connection = await pool.getConnection();
        const itemSchema = await getItemSchemaSupport(connection);
        const queueLimitExpr = getItemQueueLimitExpression(itemSchema);
        const imageExpr = getItemImageExpression(itemSchema);
        const statusExpr = getItemStatusExpression(itemSchema);

        const [itemRows] = await connection.query(`
            SELECT
                i.iditem,
                i.titulo,
                i.descricao,
                i.usuario_idusuario,
                i.latitude,
                i.longitude,
                ${queueLimitExpr} AS limite_fila,
                ${imageExpr} AS imagem_url,
                ${statusExpr} AS status
            FROM item i
            WHERE i.iditem = ?
        `, [iditem]);

        if (itemRows.length === 0) {
            return res.status(404).json({ erro: 'Item não encontrado' });
        }

        const item = itemRows[0];
        if (item.status !== 'disponivel' && Number(item.usuario_idusuario) !== Number(req.user.idusuario)) {
            const [relationship] = await connection.query(
                'SELECT 1 FROM solicitacao WHERE item_iditem = ? AND usuario_idusuario = ? LIMIT 1',
                [iditem, req.user.idusuario]
            );
            if (relationship.length === 0) {
                return res.status(403).json({ erro: 'Você não tem acesso à fila deste item' });
            }
        }

        const [fila] = await connection.query(`
            SELECT
                u.idusuario,
                u.primeironome,
                u.sobrenome,
                u.latitude,
                u.longitude,
                s.idsolicitacao,
                s.datarequisicao,
                s.status
            FROM solicitacao s
            JOIN usuario u ON s.usuario_idusuario = u.idusuario
            WHERE s.item_iditem = ? AND s.status = 'pendente'
        `, [iditem]);

        const filaOrdenada = calculateQueueCandidates(item, fila).map((row, index) => ({
            posicao: index + 1,
            nome: `${row.primeironome || ''} ${row.sobrenome || ''}`.trim() || 'Usuário',
            datarequisicao: row.datarequisicao,
            status: row.status,
            is_me: Number(row.idusuario) === Number(req.user.idusuario)
        }));

        res.json({
            item: {
                iditem: item.iditem,
                titulo: item.titulo,
                descricao: item.descricao,
                imagem_url: item.imagem_url,
                limite_fila: Number(item.limite_fila || 10),
                status: item.status || 'disponivel'
            },
            total: filaOrdenada.length,
            fila: filaOrdenada,
            atualizado_em: new Date().toISOString()
        });
    } catch (error) {
        handleError(res, 500, 'Erro ao carregar fila completa', error);
    } finally {
        if (connection) connection.release();
    }
});

const handleFilaAlias = async (req, res) => {
    let connection;
    try {
        const iditem = req.params.iditem || req.query.iditem;
        if (!validator.isValidID(iditem)) {
            return res.status(400).json({ erro: 'ID do item inválido' });
        }

        connection = await pool.getConnection();
        const [itemRows] = await connection.query(
            'SELECT usuario_idusuario FROM item WHERE iditem = ?',
            [iditem]
        );

        if (itemRows.length === 0) {
            return res.status(404).json({ erro: 'Item não encontrado' });
        }

        if (Number(itemRows[0].usuario_idusuario) === Number(req.user.idusuario)) {
            const userSchema = await getUserSchemaSupport(connection);
            const photoExpr = getUserPhotoExpression(userSchema);
            const [itemLocationRows] = await connection.query(
                'SELECT latitude, longitude FROM item WHERE iditem = ?',
                [iditem]
            );
            const [fila] = await connection.query(`
                SELECT
                    u.idusuario,
                    u.primeironome,
                    u.sobrenome,
                    ${photoExpr} AS foto_url,
                    u.latitude,
                    u.longitude,
                    s.idsolicitacao,
                    s.datarequisicao,
                    s.status
                FROM solicitacao s
                JOIN usuario u ON s.usuario_idusuario = u.idusuario
                WHERE s.item_iditem = ? AND s.status = 'pendente'
            `, [iditem]);

            const filaOrdenada = calculateQueueCandidates(itemLocationRows[0], fila).map((row, index) => ({
                idusuario: row.idusuario,
                primeironome: row.primeironome,
                sobrenome: row.sobrenome,
                foto_url: row.foto_url,
                idsolicitacao: row.idsolicitacao,
                datarequisicao: row.datarequisicao,
                status: row.status,
                posicao: index + 1,
                distancia_km: Number(row.distancia_km.toFixed(2))
            }));

            return res.json(filaOrdenada);
        }

        const itemSchema = await getItemSchemaSupport(connection);
        const dateExpr = getItemDateExpression(itemSchema);
        const intervalExpr = itemSchema.hasPrazoDias ? 'i.prazo_dias' : '7';
        const [itemLocationRows] = await connection.query(`
            SELECT i.iditem, i.latitude, i.longitude,
                DATEDIFF(DATE_ADD(${dateExpr}, INTERVAL ${intervalExpr} DAY), NOW()) AS dias_restantes
            FROM item i
            WHERE i.iditem = ?
        `, [iditem]);

        const [candidatos] = await connection.query(`
            SELECT s.idsolicitacao, s.usuario_idusuario, s.datarequisicao, u.latitude, u.longitude
            FROM solicitacao s
            JOIN usuario u ON s.usuario_idusuario = u.idusuario
            WHERE s.item_iditem = ? AND s.status = 'pendente'
        `, [iditem]);

        const filaOrdenada = calculateQueueCandidates(itemLocationRows[0], candidatos);
        const positionIndex = filaOrdenada.findIndex((row) => Number(row.usuario_idusuario) === Number(req.user.idusuario));
        if (positionIndex === -1) {
            return res.status(404).json({ erro: 'Fila não encontrada para este item ou você não está na fila' });
        }

        const fila = filaOrdenada[positionIndex];
        res.json({
            posicao: positionIndex + 1,
            total: filaOrdenada.length,
            distancia_km: Number(fila.distancia_km.toFixed(2)),
            dias_restantes: Math.max(0, Number(itemLocationRows[0].dias_restantes))
        });
    } catch (error) {
        handleError(res, 500, 'Erro ao carregar fila', error);
    } finally {
        if (connection) connection.release();
    }
};

app.get('/api/fila', authMiddleware, handleFilaAlias);
app.get('/api/fila/:iditem', authMiddleware, handleFilaAlias);

// Finalizar doação antecipadamente
app.post('/api/itens/:iditem/finalizar', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { iditem } = req.params;
        if (!validator.isValidID(iditem)) {
            return res.status(400).json({ erro: 'ID do item inválido' });
        }

        connection = await pool.getConnection();
        const result = await runFinalizeItemFlow(connection, iditem, req.user.idusuario);
        res.json(result);
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({ erro: error.message });
        }
        handleError(res, 500, 'Erro ao finalizar doação', error);
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/finalizar', authMiddleware, async (req, res) => {
    let connection;
    try {
        const iditem = req.body?.iditem ?? req.body?.item_iditem ?? req.query?.iditem;
        if (!validator.isValidID(iditem)) {
            return res.status(400).json({ erro: 'ID do item inválido' });
        }

        connection = await pool.getConnection();
        const result = await runFinalizeItemFlow(connection, iditem, req.user.idusuario);
        res.json(result);
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({ erro: error.message });
        }
        handleError(res, 500, 'Erro ao finalizar doação', error);
    } finally {
        if (connection) connection.release();
    }
});

// Aceitar solicitação
app.post('/api/aceitar-solicitacao/:idsolicitacao', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { idsolicitacao } = req.params;

        if (!validator.isValidID(idsolicitacao)) {
            return res.status(400).json({ erro: 'ID de solicitação inválido' });
        }

        connection = await pool.getConnection();

        // Verificar se é o doador
        const [solicitacoes] = await connection.query(`
            SELECT
                s.idsolicitacao,
                s.item_iditem,
                s.usuario_idusuario AS beneficiario,
                s.status,
                i.usuario_idusuario AS doador
            FROM solicitacao s
            JOIN item i ON s.item_iditem = i.iditem
            WHERE s.idsolicitacao = ?
        `, [idsolicitacao]);

        if (solicitacoes.length === 0) {
            return res.status(404).json({ erro: 'Solicitação não encontrada' });
        }

        const doadorId = Number(solicitacoes[0].doador);
        const beneficiarioId = Number(solicitacoes[0].beneficiario);
        const usuarioId = Number(req.user.idusuario);

        if (doadorId !== usuarioId) {
            return res.status(403).json({ erro: 'Você não tem permissão' });
        }

        await connection.beginTransaction();
        try {
            const aceita = await acceptSolicitation(connection, solicitacoes[0], doadorId);
            await connection.commit();
            res.json({
                sucesso: true,
                status: 'reservada',
                iditem: aceita.iditem,
                idsolicitacao: aceita.idsolicitacao,
                idusuario_beneficiario: aceita.beneficiarioId
            });
        } catch (e) {
            await connection.rollback();
            if (e.statusCode) {
                return res.status(e.statusCode).json({ erro: e.message });
            }
            throw e;
        }
    } catch (error) {
        handleError(res, 500, 'Erro ao aceitar solicitação', error);
    } finally {
        if (connection) connection.release();
    }
});

// Cancelar / reverter solicitação
app.post('/api/cancelar-solicitacao/:idsolicitacao', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { idsolicitacao } = req.params;

        if (!validator.isValidID(idsolicitacao)) {
            return res.status(400).json({ erro: 'ID de solicitação inválido' });
        }

        connection = await pool.getConnection();
        const [rows] = await connection.query(`
            SELECT 
                s.status,
                s.usuario_idusuario AS solicitante,
                i.usuario_idusuario AS doador,
                s.item_iditem
            FROM solicitacao s
            JOIN item i ON s.item_iditem = i.iditem
            WHERE s.idsolicitacao = ?
        `, [idsolicitacao]);

        if (rows.length === 0) {
            return res.status(404).json({ erro: 'Solicitação não encontrada' });
        }

        const solicitacao = rows[0];
        const usuarioId = Number(req.user.idusuario);

        if (usuarioId !== Number(solicitacao.solicitante) && usuarioId !== Number(solicitacao.doador)) {
            return res.status(403).json({ erro: 'Você não tem permissão para cancelar esta solicitação' });
        }

        if (solicitacao.status === 'cancelado') {
            return res.status(400).json({ erro: 'Solicitação já está cancelada' });
        }

        await connection.query(
            'UPDATE solicitacao SET status = ? WHERE idsolicitacao = ?',
            ['cancelado', idsolicitacao]
        );

        res.json({ sucesso: true });
    } catch (error) {
        handleError(res, 500, 'Erro ao cancelar solicitação', error);
    } finally {
        if (connection) connection.release();
    }
});

// Confirmar entrega
app.post('/api/confirmar-entrega/:idsolicitacao', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { idsolicitacao } = req.params;

        if (!validator.isValidID(idsolicitacao)) {
            return res.status(400).json({ erro: 'ID inválido' });
        }

        connection = await pool.getConnection();

        // Verificar permissão (quem solicitou ou doador)
        const [solicitacoes] = await connection.query(`
            SELECT
                s.idsolicitacao,
                s.item_iditem,
                s.usuario_idusuario AS solicitante,
                s.usuario_idusuario,
                s.status,
                i.iditem,
                i.usuario_idusuario AS doador
            FROM solicitacao s
            JOIN item i ON s.item_iditem = i.iditem
            WHERE s.idsolicitacao = ?
        `, [idsolicitacao]);

        if (solicitacoes.length === 0) {
            return res.status(404).json({ erro: 'Solicitação não encontrada' });
        }

        const sol = solicitacoes[0];
        const solicitanteId = Number(sol.solicitante);
        const doadorId = Number(sol.doador);
        const usuarioId = Number(req.user.idusuario);

        if (solicitanteId !== usuarioId && doadorId !== usuarioId) {
            return res.status(403).json({ erro: 'Você não tem permissão' });
        }

        if (!ACCEPTED_STATUSES.includes(sol.status)) {
            return res.status(409).json({ erro: 'A doação ainda não está aguardando entrega' });
        }

        await connection.beginTransaction();
        try {
            const item = {
                iditem: sol.item_iditem,
                usuario_idusuario: sol.doador
            };
            const finalizada = await finalizeAcceptedDonation(connection, item, {
                idsolicitacao: sol.idsolicitacao,
                usuario_idusuario: sol.solicitante
            });
            await connection.commit();
            res.json({
                sucesso: true,
                status: 'finalizada',
                iditem: finalizada.iditem,
                idsolicitacao: finalizada.idsolicitacao,
                idusuario_doador: finalizada.doadorId,
                idusuario_beneficiario: finalizada.beneficiarioId,
                papel_usuario: Number(req.user.idusuario) === Number(finalizada.doadorId) ? 'doador' : 'beneficiario'
            });
        } catch (e) {
            await connection.rollback();
            throw e;
        }
    } catch (error) {
        handleError(res, 500, 'Erro ao confirmar entrega', error);
    } finally {
        if (connection) connection.release();
    }
});

// Carregar atividades (minhas solicitações e avaliações)
app.get('/api/atividades', authMiddleware, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await ensureAvaliacaoSchema(connection);
        const itemSchema = await getItemSchemaSupport(connection);
        const dateExpr = getItemDateExpression(itemSchema);
        const imageExpr = getItemImageExpression(itemSchema);
        const statusExpr = getItemStatusExpression(itemSchema);
        const usuarioId = Number(req.user.idusuario);

        const [solicitacoes] = await connection.query(`
            SELECT 
                'solicitacao' as tipo,
                s.idsolicitacao as id,
                s.datarequisicao as data,
                s.status,
                i.iditem,
                i.titulo,
                i.descricao,
                ${imageExpr} AS imagem_url,
                ${statusExpr} AS item_status,
                u.primeironome,
                u.idusuario as idusuario_doador,
                s.usuario_idusuario as idusuario_beneficiario,
                NULL as beneficiario_nome,
                EXISTS(
                    SELECT 1 FROM avaliacao a
                    WHERE a.idsolicitacao = s.idsolicitacao
                      AND a.idusuario_avaliador = ?
                      AND a.tipo_avaliacao = ?
                ) as avaliacao_enviada,
                NULL as avaliacao,
                NULL as comentario
            FROM solicitacao s
            JOIN item i ON s.item_iditem = i.iditem
            JOIN usuario u ON i.usuario_idusuario = u.idusuario
            WHERE s.usuario_idusuario = ?
        `, [usuarioId, EVALUATION_TYPES.BENEFICIARY_RATES_DONOR_ITEM, usuarioId]);

        const [doacoes] = await connection.query(`
            SELECT
                'doacao' as tipo,
                i.iditem as id,
                i.iditem,
                ${dateExpr} as data,
                ${statusExpr} as status,
                i.titulo,
                i.descricao,
                ${imageExpr} AS imagem_url,
                s_ent.idsolicitacao,
                s_ent.status AS entrega_status,
                b.idusuario as idusuario_beneficiario,
                b.primeironome as beneficiario_nome,
                EXISTS(
                    SELECT 1 FROM avaliacao a
                    WHERE a.idsolicitacao = s_ent.idsolicitacao
                      AND a.idusuario_avaliador = ?
                      AND a.tipo_avaliacao = ?
                ) as avaliacao_enviada,
                NULL as primeironome,
                NULL as avaliacao,
                NULL as comentario
            FROM item i
            LEFT JOIN solicitacao s_ent
                ON s_ent.item_iditem = i.iditem
               AND s_ent.status IN ('aceito', 'reservado', 'aguardando_entrega', 'em_processo', 'entregue')
            LEFT JOIN usuario b ON b.idusuario = s_ent.usuario_idusuario
            WHERE i.usuario_idusuario = ?
        `, [usuarioId, EVALUATION_TYPES.DONOR_RATES_BENEFICIARY, usuarioId]);

        const [avaliacoes] = await connection.query(`
            SELECT 
                'avaliacao' as tipo,
                a.idavaliacao as id,
                a.dataavaliacao as data,
                'concluida' as status,
                NULL as titulo,
                NULL as descricao,
                u.primeironome,
                a.iditem,
                a.idsolicitacao,
                a.tipo_avaliacao,
                a.ocorreu_tudo_bem,
                a.encontrou_pessoa,
                a.item_conforme,
                a.sem_problemas,
                a.imagem_feedback_url,
                a.avaliacao,
                a.comentario
            FROM avaliacao a
            JOIN usuario u ON a.idusuario_avaliado = u.idusuario
            WHERE a.idusuario_avaliador = ?
        `, [usuarioId]);

        const atividades = [...doacoes, ...solicitacoes, ...avaliacoes].sort((a, b) => new Date(b.data) - new Date(a.data));

        res.json(atividades);
    } catch (error) {
        handleError(res, 500, 'Erro ao carregar atividades', error);
    } finally {
        if (connection) connection.release();
    }
});

// Contar mensagens não lidas (para badge de notificação)
app.get('/api/mensagens/nao-lidas', authMiddleware, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        try {
            const [rows] = await connection.query(
                'SELECT COUNT(*) AS total FROM mensagem WHERE usuario_idusuario1 = ? AND lida = FALSE',
                [req.user.idusuario]
            );
            res.json({ total: Number(rows[0].total) });
        } catch (dbError) {
            // Coluna lida pode não existir em bancos antigos — retorna 0 sem crash
            if (dbError.code === 'ER_BAD_FIELD_ERROR') {
                return res.json({ total: 0 });
            }
            throw dbError;
        }
    } catch (error) {
        handleError(res, 500, 'Erro ao contar mensagens não lidas', error);
    } finally {
        if (connection) connection.release();
    }
});

// Marcar mensagens de uma conversa como lidas
app.post('/api/mensagens/marcar-lidas/:idusuario', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { idusuario } = req.params;
        if (!validator.isValidID(idusuario)) {
            return res.status(400).json({ erro: 'ID de usuário inválido' });
        }
        connection = await pool.getConnection();
        const messageSchema = await getMessageSchemaSupport(connection);
        if (!messageSchema.hasLida) {
            return res.json({ sucesso: true });
        }
        await connection.query(
            'UPDATE mensagem SET lida = TRUE WHERE usuario_idusuario = ? AND usuario_idusuario1 = ? AND lida = FALSE',
            [idusuario, req.user.idusuario]
        );
        res.json({ sucesso: true });
    } catch (error) {
        handleError(res, 500, 'Erro ao marcar mensagens como lidas', error);
    } finally {
        if (connection) connection.release();
    }
});

// Listar chats (conversas)
app.get('/api/chats', authMiddleware, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const messageSchema = await getMessageSchemaSupport(connection);
        const dateColumn = getMessageDateColumn(messageSchema);
        const lastMessageExpr = dateColumn ? `MAX(m.\`${dateColumn}\`)` : 'NOW()';

        // Consulta robusta que funciona em MySQL 5.7 e 8.0 (evita problemas de ONLY_FULL_GROUP_BY)
        const [chats] = await connection.query(`
            SELECT 
                u.idusuario AS idusuario_outro,
                u.primeironome,
                ${lastMessageExpr} AS ultima_mensagem,
                MAX(m.idmensagem) AS ultima_ordem
            FROM mensagem m
            JOIN usuario u ON u.idusuario = (CASE WHEN m.usuario_idusuario = ? THEN m.usuario_idusuario1 ELSE m.usuario_idusuario END)
            WHERE m.usuario_idusuario = ? OR m.usuario_idusuario1 = ?
            GROUP BY u.idusuario, u.primeironome
            ORDER BY ultima_ordem DESC
        `, [req.user.idusuario, req.user.idusuario, req.user.idusuario]);

        res.json(chats || []);
    } catch (error) {
        console.error('Erro na rota /api/chats:', error);
        handleError(res, 500, 'Erro ao carregar chats', error);
    } finally {
        if (connection) connection.release();
    }
});

// Carregar mensagens de uma conversa
app.get('/api/chat/:idusuario', authMiddleware, async (req, res) => {
    let connection;
    try {
        const { idusuario } = req.params;

        if (!validator.isValidID(idusuario)) {
            return res.status(400).json({ erro: 'ID de usuário inválido' });
        }

        connection = await pool.getConnection();
        const [usuarios] = await connection.query('SELECT idusuario FROM usuario WHERE idusuario = ?', [idusuario]);
        if (usuarios.length === 0) {
            return res.status(404).json({ erro: 'Usuário não encontrado' });
        }

        if (!(await canUsersChat(connection, req.user.idusuario, idusuario))) {
            return res.status(403).json({ erro: 'Chat indisponível para estes usuários' });
        }

        const messageSchema = await getMessageSchemaSupport(connection);
        const dateColumn = getMessageDateColumn(messageSchema);
        const dateSelect = dateColumn ? `m.\`${dateColumn}\`` : 'NULL';
        const orderExpr = dateColumn ? `m.\`${dateColumn}\` ASC, m.idmensagem ASC` : 'm.idmensagem ASC';

        const [mensagens] = await connection.query(`
            SELECT 
                m.idmensagem,
                m.usuario_idusuario AS idusuario_remetente,
                m.conteudo AS mensagem,
                ${dateSelect} AS data,
                u.primeironome
            FROM mensagem m
            JOIN usuario u ON m.usuario_idusuario = u.idusuario
            WHERE (
                (m.usuario_idusuario = ? AND m.usuario_idusuario1 = ?)
                OR (m.usuario_idusuario = ? AND m.usuario_idusuario1 = ?)
            )
            ORDER BY ${orderExpr}
            LIMIT 100
        `, [req.user.idusuario, idusuario, idusuario, req.user.idusuario]);

        res.json(mensagens);
    } catch (error) {
        handleError(res, 500, 'Erro ao carregar mensagens', error);
    } finally {
        if (connection) connection.release();
    }
});

// Enviar mensagem
app.post('/api/mensagem', authMiddleware, async (req, res) => {
    let connection;
    try {
        const idusuario_destinatario = req.body?.idusuario_destinatario ?? req.body?.destinatario_idusuario ?? req.body?.idusuario1 ?? req.body?.destinatarioId;
        const mensagem = req.body?.mensagem ?? req.body?.conteudo;

        if (!validator.isValidID(idusuario_destinatario) || !validator.isValidMessage(mensagem)) {
            return res.status(400).json({ erro: 'Dados de mensagem inválidos' });
        }

        if (Number(idusuario_destinatario) === Number(req.user.idusuario)) {
            return res.status(400).json({ erro: 'Não é possível enviar mensagem para si mesmo' });
        }

        connection = await pool.getConnection();
        const [usuarios] = await connection.query('SELECT idusuario FROM usuario WHERE idusuario = ?', [idusuario_destinatario]);
        if (usuarios.length === 0) {
            return res.status(404).json({ erro: 'Destinatário não encontrado' });
        }

        if (!(await canUsersChat(connection, req.user.idusuario, idusuario_destinatario))) {
            return res.status(403).json({ erro: 'Chat indisponível para estes usuários' });
        }

        const idmensagem = await insertChatMessage(connection, req.user.idusuario, idusuario_destinatario, mensagem);

        res.status(201).json({ sucesso: true, idmensagem });
    } catch (error) {
        handleError(res, 500, 'Erro ao enviar mensagem', error);
    } finally {
        if (connection) connection.release();
    }
});

// Avaliar experiência de doação
app.post('/api/avaliacao', authMiddleware, async (req, res) => {
    let connection;
    try {
        const {
            idusuario_avaliado,
            idsolicitacao,
            iditem,
            tipo_avaliacao,
            avaliacao,
            comentario,
            ocorreu_tudo_bem,
            encontrou_pessoa,
            item_conforme,
            sem_problemas,
            imagem_feedback_url
        } = req.body;

        const nota = Number(avaliacao);
        if (!validator.isValidID(idusuario_avaliado) || !Number.isInteger(nota) || nota < 1 || nota > 5) {
            return res.status(400).json({ erro: 'Dados de avaliação inválidos' });
        }

        connection = await pool.getConnection();
        await ensureAvaliacaoSchema(connection);

        const comentarioSanitized = escapeHtml(comentario?.trim() || '');
        const usuarioId = Number(req.user.idusuario);
        const avaliadoId = Number(idusuario_avaliado);
        const tipo = Object.values(EVALUATION_TYPES).includes(tipo_avaliacao)
            ? tipo_avaliacao
            : null;

        if (idsolicitacao) {
            if (!validator.isValidID(idsolicitacao)) {
                return res.status(400).json({ erro: 'ID de solicitação inválido' });
            }

            const [solicitacoes] = await connection.query(`
                SELECT
                    s.idsolicitacao,
                    s.item_iditem,
                    s.usuario_idusuario AS beneficiario,
                    s.status,
                    i.usuario_idusuario AS doador
                FROM solicitacao s
                JOIN item i ON s.item_iditem = i.iditem
                WHERE s.idsolicitacao = ?
            `, [idsolicitacao]);

            if (solicitacoes.length === 0) {
                return res.status(404).json({ erro: 'Solicitação não encontrada' });
            }

            const solicitacao = solicitacoes[0];
            if (solicitacao.status !== 'entregue') {
                return res.status(409).json({ erro: 'A avaliação só pode ser feita depois da entrega finalizada' });
            }

            const tipoResolvido = tipo || (
                usuarioId === Number(solicitacao.doador)
                    ? EVALUATION_TYPES.DONOR_RATES_BENEFICIARY
                    : EVALUATION_TYPES.BENEFICIARY_RATES_DONOR_ITEM
            );

            if (tipoResolvido === EVALUATION_TYPES.DONOR_RATES_BENEFICIARY) {
                if (usuarioId !== Number(solicitacao.doador) || avaliadoId !== Number(solicitacao.beneficiario)) {
                    return res.status(403).json({ erro: 'Somente o doador pode avaliar o beneficiário desta doação' });
                }
            } else if (tipoResolvido === EVALUATION_TYPES.BENEFICIARY_RATES_DONOR_ITEM) {
                if (usuarioId !== Number(solicitacao.beneficiario) || avaliadoId !== Number(solicitacao.doador)) {
                    return res.status(403).json({ erro: 'Somente o beneficiário pode avaliar o item e o doador desta doação' });
                }
            } else {
                return res.status(400).json({ erro: 'Tipo de avaliação inválido' });
            }

            const [duplicadas] = await connection.query(`
                SELECT idavaliacao FROM avaliacao
                WHERE idsolicitacao = ?
                  AND tipo_avaliacao = ?
                  AND idusuario_avaliador = ?
                LIMIT 1
            `, [idsolicitacao, tipoResolvido, usuarioId]);

            if (duplicadas.length > 0) {
                return res.status(409).json({ erro: 'Você já avaliou esta experiência' });
            }

            const imagemFeedbackPersistida = tipoResolvido === EVALUATION_TYPES.BENEFICIARY_RATES_DONOR_ITEM
                ? await persistFeedbackImage(imagem_feedback_url)
                : '';

            const [result] = await connection.query(`
                INSERT INTO avaliacao (
                    idusuario_avaliador,
                    idusuario_avaliado,
                    idsolicitacao,
                    iditem,
                    tipo_avaliacao,
                    avaliacao,
                    comentario,
                    ocorreu_tudo_bem,
                    encontrou_pessoa,
                    item_conforme,
                    sem_problemas,
                    imagem_feedback_url,
                    dataavaliacao
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
            `, [
                usuarioId,
                avaliadoId,
                Number(idsolicitacao),
                Number(iditem || solicitacao.item_iditem),
                tipoResolvido,
                nota,
                comentarioSanitized,
                toBooleanOrNull(ocorreu_tudo_bem),
                toBooleanOrNull(encontrou_pessoa),
                tipoResolvido === EVALUATION_TYPES.BENEFICIARY_RATES_DONOR_ITEM ? toBooleanOrNull(item_conforme) : null,
                toBooleanOrNull(sem_problemas),
                imagemFeedbackPersistida || null
            ]);

            return res.status(201).json({ sucesso: true, idavaliacao: result.insertId });
        }

        // Compatibilidade com chamadas antigas sem idsolicitacao.
        if (usuarioId === avaliadoId) {
            return res.status(400).json({ erro: 'Você não pode avaliar a si mesmo' });
        }

        if (!(await usersHaveDonationRelationship(connection, usuarioId, avaliadoId, ['entregue']))) {
            return res.status(403).json({ erro: 'A avaliação só é permitida após uma doação concluída entre os usuários' });
        }

        const [duplicadasGenericas] = await connection.query(`
            SELECT idavaliacao FROM avaliacao
            WHERE idsolicitacao IS NULL
              AND idusuario_avaliador = ?
              AND idusuario_avaliado = ?
            LIMIT 1
        `, [usuarioId, avaliadoId]);

        if (duplicadasGenericas.length > 0) {
            return res.status(409).json({ erro: 'Você já avaliou este usuário' });
        }

        const [result] = await connection.query(
            'INSERT INTO avaliacao (idusuario_avaliador, idusuario_avaliado, avaliacao, comentario, dataavaliacao) VALUES (?, ?, ?, ?, NOW())',
            [usuarioId, avaliadoId, nota, comentarioSanitized]
        );

        res.status(201).json({ sucesso: true, idavaliacao: result.insertId });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ erro: 'Você já avaliou esta experiência' });
        }
        handleError(res, 500, 'Erro ao enviar avaliação', error);
    } finally {
        if (connection) connection.release();
    }
});

// Perfil do usuário
app.get('/api/perfil', authMiddleware, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [users] = await connection.query(
            'SELECT idusuario, primeironome, sobrenome, email, ddd, telefone, logradouro, bairro, numero, cidade, estado, latitude, longitude FROM usuario WHERE idusuario = ?',
            [req.user.idusuario]
        );

        res.json(users[0]);
    } catch (error) {
        handleError(res, 500, 'Erro ao carregar perfil', error);
    } finally {
        if (connection) connection.release();
    }
});

// Atualizar perfil
app.put('/api/perfil', authMiddleware, async (req, res) => {
    let connection;
    try {
        const body = sanitizeObject(req.body || {});
        const {
            primeironome = '',
            sobrenome = '',
            ddd = '',
            telefone = '',
            logradouro = '',
            bairro = '',
            numero = '',
            cidade = '',
            estado = '',
            latitude,
            longitude
        } = body;

        if (!validator.isValidName(primeironome) || !validator.isValidCoordinates(latitude, longitude) || 
            !validator.isValidStreet(logradouro) || !validator.isValidNumber(numero) || 
            !validator.isValidCity(cidade) || !validator.isValidState(estado) || !validator.isValidDDD(ddd)) {
            return res.status(400).json({ erro: 'Dados de perfil inválidos' });
        }

        const userData = {
            primeironome: escapeHtml(normalizeString(primeironome)),
            sobrenome: escapeHtml(normalizeString(sobrenome)),
            ddd: normalizeString(ddd),
            telefone: normalizePhone(telefone),
            logradouro: escapeHtml(normalizeString(logradouro)),
            bairro: escapeHtml(normalizeString(bairro)),
            numero: escapeHtml(normalizeString(numero)),
            cidade: escapeHtml(normalizeString(cidade)),
            estado: normalizeState(estado),
            latitude: parseFloat(latitude),
            longitude: parseFloat(longitude)
        };

        connection = await pool.getConnection();
        await connection.query(
            'UPDATE usuario SET primeironome = ?, sobrenome = ?, ddd = ?, telefone = ?, logradouro = ?, bairro = ?, numero = ?, cidade = ?, estado = ?, latitude = ?, longitude = ? WHERE idusuario = ?',
            [userData.primeironome, userData.sobrenome, userData.ddd, userData.telefone, userData.logradouro, userData.bairro, userData.numero, userData.cidade, userData.estado, userData.latitude, userData.longitude, req.user.idusuario]
        );

        res.json({ sucesso: true });
    } catch (error) {
        handleError(res, 500, 'Erro ao atualizar perfil', error);
    } finally {
        if (connection) connection.release();
    }
});

// Recuperar senha (gera token de reset — para testes retorna o token no body)
app.post('/api/recuperar-senha', async (req, res) => {
    let connection;
    try {
        const { email } = req.body || {};

        if (!validator.isValidEmail(email)) {
            return res.status(400).json({ erro: 'Email inválido' });
        }

        connection = await pool.getConnection();
        const [users] = await connection.query('SELECT idusuario FROM usuario WHERE email = ?', [email]);

        // Sempre responder com sucesso para evitar enumeração de contas
        if (users.length === 0) {
            return res.json({ sucesso: true });
        }

        const token = crypto.randomBytes(24).toString('hex');
        const expires = Date.now() + (15 * 60 * 1000); // 15 minutos
        passwordResetTokens.set(token, { email, expires });

        // Em produção enviar por email. Para testes retornamos o token no body.
        res.json({ sucesso: true, token });
    } catch (error) {
        handleError(res, 500, 'Erro ao gerar token de recuperação', error);
    } finally {
        if (connection) connection.release();
    }
});

// Resetar senha usando token
app.post('/api/resetar-senha', async (req, res) => {
    let connection;
    try {
        const { token, novaSenha } = req.body || {};

        if (!token || !validator.isValidPassword(novaSenha)) {
            return res.status(400).json({ erro: 'Dados inválidos' });
        }

        const record = passwordResetTokens.get(token);
        if (!record || record.expires < Date.now()) {
            return res.status(400).json({ erro: 'Token inválido ou expirado' });
        }

        connection = await pool.getConnection();
        const senhaHash = await hashPassword(novaSenha);
        await connection.query('UPDATE usuario SET senha = ? WHERE email = ?', [senhaHash, record.email]);

        passwordResetTokens.delete(token);
        res.json({ sucesso: true });
    } catch (error) {
        handleError(res, 500, 'Erro ao resetar senha', error);
    } finally {
        if (connection) connection.release();
    }
});

async function processarFilasExpiradas() {
    let connection;
    try {
        connection = await pool.getConnection();
        const itemSchema = await getItemSchemaSupport(connection);
        const dateExpr = getItemDateExpression(itemSchema);
        const intervalExpr = itemSchema.hasPrazoDias ? 'INTERVAL i.prazo_dias DAY' : 'INTERVAL 7 DAY';

        const [itensExpirados] = await connection.query(`
            SELECT i.iditem, i.usuario_idusuario, ${itemSchema.hasPrazoDias ? 'i.prazo_dias,' : '7 AS prazo_dias,'}
                ${dateExpr} AS dtcriacao,
                u_item.latitude AS lat_item, u_item.longitude AS lon_item
            FROM item i
            JOIN usuario u_item ON i.usuario_idusuario = u_item.idusuario
            WHERE ${dateExpr} <= DATE_SUB(NOW(), ${intervalExpr})
              AND EXISTS (
                SELECT 1 FROM solicitacao s 
                WHERE s.item_iditem = i.iditem AND s.status = 'pendente'
              )
              AND NOT EXISTS (
                SELECT 1 FROM item_processamento ip WHERE ip.iditem = i.iditem
              )
        `);

        for (const item of itensExpirados) {
            await connection.beginTransaction();
            try {
                const [candidatos] = await connection.query(`
                    SELECT s.idsolicitacao, s.usuario_idusuario,
                        (6371 * ACOS(
                            COS(RADIANS(?)) * COS(RADIANS(u.latitude)) *
                            COS(RADIANS(u.longitude) - RADIANS(?)) +
                            SIN(RADIANS(?)) * SIN(RADIANS(u.latitude))
                        )) AS distancia_km
                    FROM solicitacao s
                    JOIN usuario u ON s.usuario_idusuario = u.idusuario
                    WHERE s.item_iditem = ? AND s.status = 'pendente'
                    ORDER BY distancia_km ASC
                    LIMIT 1
                `, [item.lat_item, item.lon_item, item.lat_item, item.iditem]);

                if (candidatos.length > 0) {
                    const vencedor = candidatos[0];
                    await connection.query(
                        "UPDATE solicitacao SET status = 'aguardando_entrega' WHERE idsolicitacao = ?",
                        [vencedor.idsolicitacao]
                    );
                    await connection.query(
                        "UPDATE solicitacao SET status = 'cancelado' WHERE item_iditem = ? AND idsolicitacao != ? AND status = 'pendente'",
                        [item.iditem, vencedor.idsolicitacao]
                    );
                    await markItemStatus(connection, item.iditem, 'reservada');
                    await registerItemProcessing(connection, item.iditem);
                    await insertChatMessage(connection, item.usuario_idusuario, vencedor.usuario_idusuario, AUTO_ACCEPT_MESSAGE);
                }

                await connection.commit();
            } catch (e) {
                await connection.rollback();
                console.error('Erro ao processar item', item.iditem, e.message);
            }
        }
    } catch (err) {
        console.error('Erro geral em processarFilasExpiradas:', err.message);
    } finally {
        if (connection) connection.release();
    }
}

if (require.main === module) {
    pool.getConnection()
        .then(async (connection) => {
            try {
                await ensureAvaliacaoSchema(connection);
                console.log('✓ Schema de avaliações verificado');
            } finally {
                connection.release();
            }
        })
        .catch((err) => console.error('Erro ao verificar schema de avaliações:', err.message));

    setInterval(processarFilasExpiradas, 60 * 60 * 1000);
    processarFilasExpiradas().catch((err) => console.error('Erro inicial ao processar filas expiradas:', err));
}

// ============= FALLBACK =============
/**
 * SPA fallback:
 * - Para rotas NÃO-API, servimos index.html
 * - Para rotas começando com /api, retornamos JSON para evitar o frontend tentar parsear HTML como JSON
 */
app.use((req, res, next) => {
    if (req.path?.startsWith('/api')) {
        return res.status(404).json({ erro: 'Rota não encontrada' });
    }
    const indexPath = frontendPath ? path.join(frontendPath, 'index.html') : null;
    if (indexPath && fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.status(200).json({ status: 'DoeFacil API online', docs: '/health' });
    }
});

// ============= INICIAR SERVIDOR =============
const PORT = process.env.PORT || 3001;
if (require.main === module) {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`✓ Servidor rodando em http://localhost:${PORT}`);
        console.log(`✓ Servidor rodando em http://127.0.0.1:${PORT}`);
        console.log(`✓ Environment: ${process.env.NODE_ENV}`);
        console.log(`✓ CORS origins: ${process.env.CORS_ORIGIN}`);
    });
}

module.exports = { app, processarFilasExpiradas };
