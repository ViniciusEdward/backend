-- =====================================================
-- Doefacil - Migration Script
-- =====================================================

CREATE TABLE IF NOT EXISTS usuario (
    idusuario INT PRIMARY KEY AUTO_INCREMENT,
    primeironome VARCHAR(100) NOT NULL,
    sobrenome VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    cpf VARCHAR(14) NOT NULL UNIQUE,
    ddd VARCHAR(2) NOT NULL,
    telefone VARCHAR(9) NOT NULL,
    logradouro VARCHAR(255),
    bairro VARCHAR(100),
    numero VARCHAR(20),
    cidade VARCHAR(100),
    estado CHAR(2),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    senha VARCHAR(255) NOT NULL,
    data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    data_atualizacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    KEY idx_email (email),
    KEY idx_cpf (cpf),
    KEY idx_data_criacao (data_criacao)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS item (
    iditem INT PRIMARY KEY AUTO_INCREMENT,
    usuario_idusuario INT NOT NULL,
    titulo VARCHAR(150) NOT NULL,
    descricao TEXT,
    prazo_dias INT DEFAULT 7,
    limite_fila INT DEFAULT 10,
    imagem_url VARCHAR(2048),
    status ENUM('disponivel', 'reservada', 'finalizada') DEFAULT 'disponivel',
    datadoacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    dtcriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    FOREIGN KEY (usuario_idusuario) REFERENCES usuario(idusuario) ON DELETE CASCADE,
    KEY idx_usuario_idusuario (usuario_idusuario),
    KEY idx_datadoacao (datadoacao),
    KEY idx_dtcriacao (dtcriacao),
    KEY idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS solicitacao (
    idsolicitacao INT PRIMARY KEY AUTO_INCREMENT,
    item_iditem INT NOT NULL,
    usuario_idusuario INT NOT NULL,
    datarequisicao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('pendente', 'aceito', 'reservado', 'aguardando_entrega', 'em_processo', 'entregue', 'cancelado') DEFAULT 'pendente',
    FOREIGN KEY (item_iditem) REFERENCES item(iditem) ON DELETE CASCADE,
    FOREIGN KEY (usuario_idusuario) REFERENCES usuario(idusuario) ON DELETE CASCADE,
    KEY idx_item_iditem (item_iditem),
    KEY idx_usuario_idusuario (usuario_idusuario),
    KEY idx_status (status),
    UNIQUE KEY unique_solicitacao (item_iditem, usuario_idusuario)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS item_processamento (
    iditem INT PRIMARY KEY,
    processado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (iditem) REFERENCES item(iditem) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mensagem (
    idmensagem INT PRIMARY KEY AUTO_INCREMENT,
    usuario_idusuario INT NOT NULL,
    usuario_idusuario1 INT NOT NULL,
    conteudo TEXT NOT NULL,
    dtmensagen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lida BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (usuario_idusuario) REFERENCES usuario(idusuario) ON DELETE CASCADE,
    FOREIGN KEY (usuario_idusuario1) REFERENCES usuario(idusuario) ON DELETE CASCADE,
    KEY idx_remetente (usuario_idusuario),
    KEY idx_destinatario (usuario_idusuario1),
    KEY idx_dtmensagen (dtmensagen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS avaliacao (
    idavaliacao INT PRIMARY KEY AUTO_INCREMENT,
    idusuario_avaliador INT NOT NULL,
    idusuario_avaliado INT NOT NULL,
    idsolicitacao INT NULL,
    iditem INT NULL,
    tipo_avaliacao ENUM('doador_avalia_beneficiario', 'beneficiario_avalia_doador_item') DEFAULT 'beneficiario_avalia_doador_item',
    avaliacao INT CHECK (avaliacao >= 1 AND avaliacao <= 5),
    comentario TEXT,
    ocorreu_tudo_bem BOOLEAN DEFAULT NULL,
    encontrou_pessoa BOOLEAN DEFAULT NULL,
    item_conforme BOOLEAN DEFAULT NULL,
    sem_problemas BOOLEAN DEFAULT NULL,
    imagem_feedback_url VARCHAR(2048) DEFAULT NULL,
    dataavaliacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (idusuario_avaliador) REFERENCES usuario(idusuario) ON DELETE CASCADE,
    FOREIGN KEY (idusuario_avaliado) REFERENCES usuario(idusuario) ON DELETE CASCADE,
    FOREIGN KEY (idsolicitacao) REFERENCES solicitacao(idsolicitacao) ON DELETE SET NULL,
    FOREIGN KEY (iditem) REFERENCES item(iditem) ON DELETE SET NULL,
    KEY idx_avaliado (idusuario_avaliado),
    KEY idx_avaliacao_solicitacao (idsolicitacao),
    KEY idx_avaliacao_item (iditem),
    UNIQUE KEY unique_avaliacao_solicitacao_tipo (idsolicitacao, tipo_avaliacao, idusuario_avaliador)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS auditoria_usuarios (
    id INT PRIMARY KEY AUTO_INCREMENT,
    idusuario INT,
    acao VARCHAR(50),
    dados_antigos JSON,
    dados_novos JSON,
    data_auditoria TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_coordenadas ON item(latitude, longitude);
CREATE INDEX idx_sol_status_data ON solicitacao(status, datarequisicao);

CREATE OR REPLACE VIEW vw_itens_disponiveis AS
SELECT i.iditem, i.titulo, i.descricao, u.primeironome, u.email,
    i.latitude, i.longitude, i.datadoacao,
    COUNT(s.idsolicitacao) as num_solicitacoes
FROM item i
JOIN usuario u ON i.usuario_idusuario = u.idusuario
LEFT JOIN solicitacao s ON i.iditem = s.item_iditem AND s.status IN ('pendente', 'aceito')
GROUP BY i.iditem
HAVING num_solicitacoes < 10;

CREATE OR REPLACE VIEW vw_atividade_usuarios AS
SELECT u.idusuario, u.email,
    COUNT(DISTINCT i.iditem) as itens_doados,
    COUNT(DISTINCT s.idsolicitacao) as solicitacoes,
    COUNT(DISTINCT a.idavaliacao) as avaliacoes
FROM usuario u
LEFT JOIN item i ON u.idusuario = i.usuario_idusuario
LEFT JOIN solicitacao s ON u.idusuario = s.usuario_idusuario
LEFT JOIN avaliacao a ON u.idusuario = a.idusuario_avaliador OR u.idusuario = a.idusuario_avaliado
GROUP BY u.idusuario;




-- =====================================================
-- Migration de atualização: adiciona colunas que
-- podem faltar em bancos criados antes desta versão.
-- Seguro para executar múltiplas vezes (IF NOT EXISTS
-- no MySQL 8+ / MariaDB ou verificação manual).
-- =====================================================

-- Adicionar limite_fila em item (se não existir)
ALTER TABLE item ADD COLUMN IF NOT EXISTS limite_fila INT DEFAULT 10;

-- Adicionar imagem_url em item (se não existir)
ALTER TABLE item ADD COLUMN IF NOT EXISTS imagem_url VARCHAR(2048) DEFAULT NULL;

-- Adicionar status em item (se não existir)
ALTER TABLE item ADD COLUMN IF NOT EXISTS status ENUM('disponivel', 'reservada', 'finalizada') DEFAULT 'disponivel';

-- Adicionar prazo_dias em item (se não existir)
ALTER TABLE item ADD COLUMN IF NOT EXISTS prazo_dias INT DEFAULT 7;

-- Adicionar dtcriacao em item (se não existir — bancos antigos podem não ter)
ALTER TABLE item ADD COLUMN IF NOT EXISTS dtcriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Adicionar lida em mensagem (se não existir — necessário para badge de não lidas)
ALTER TABLE mensagem ADD COLUMN IF NOT EXISTS lida BOOLEAN DEFAULT FALSE;


-- Campos de avaliação da experiência de entrega (doador e beneficiário)
ALTER TABLE avaliacao ADD COLUMN IF NOT EXISTS idsolicitacao INT NULL;
ALTER TABLE avaliacao ADD COLUMN IF NOT EXISTS iditem INT NULL;
ALTER TABLE avaliacao ADD COLUMN IF NOT EXISTS tipo_avaliacao ENUM('doador_avalia_beneficiario', 'beneficiario_avalia_doador_item') DEFAULT 'beneficiario_avalia_doador_item';
ALTER TABLE avaliacao ADD COLUMN IF NOT EXISTS ocorreu_tudo_bem BOOLEAN DEFAULT NULL;
ALTER TABLE avaliacao ADD COLUMN IF NOT EXISTS encontrou_pessoa BOOLEAN DEFAULT NULL;
ALTER TABLE avaliacao ADD COLUMN IF NOT EXISTS item_conforme BOOLEAN DEFAULT NULL;
ALTER TABLE avaliacao ADD COLUMN IF NOT EXISTS sem_problemas BOOLEAN DEFAULT NULL;
