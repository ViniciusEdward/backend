DROP DATABASE IF EXISTS bpuflqqddr2a5zevg0hj;
CREATE DATABASE bpuflqqddr2a5zevg0hj CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE bpuflqqddr2a5zevg0hj;

CREATE TABLE usuario (
    idusuario INT PRIMARY KEY AUTO_INCREMENT,
    primeironome VARCHAR(100) NOT NULL,
    sobrenome VARCHAR(100) NOT NULL,
    cpf VARCHAR(14) NOT NULL UNIQUE,
    ddd VARCHAR(2) NOT NULL,
    telefone VARCHAR(9) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    senha VARCHAR(255) NOT NULL,
    estado VARCHAR(2) NOT NULL,
    cidade VARCHAR(100) NOT NULL,
    bairro VARCHAR(100) NOT NULL,
    logradouro VARCHAR(200) NOT NULL,
    numero VARCHAR(10) NOT NULL,
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    media_avaliacao DECIMAL(3,2) DEFAULT 0.00,
    total_avaliacoes INT DEFAULT 0,
    total_doacoes INT DEFAULT 0,
    dtcriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    token_recuperacao VARCHAR(255),
    token_expiracao TIMESTAMP,
    KEY idx_email (email),
    KEY idx_cpf (cpf),
    KEY idx_latitude (latitude),
    KEY idx_longitude (longitude)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE item (
    iditem INT PRIMARY KEY AUTO_INCREMENT,
    usuario_idusuario INT NOT NULL,
    titulo VARCHAR(150) NOT NULL,
    descricao TEXT,
    prazo_dias INT DEFAULT 7,
    limite_fila INT DEFAULT 10,
    imagem_url VARCHAR(2048),
    status ENUM('disponivel','reservada','finalizada') DEFAULT 'disponivel',
    datadoacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    dtcriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    FOREIGN KEY (usuario_idusuario) REFERENCES usuario(idusuario) ON DELETE CASCADE,
    KEY idx_usuario_idusuario (usuario_idusuario),
    KEY idx_datadoacao (datadoacao),
    KEY idx_dtcriacao (dtcriacao),
    KEY idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE item_processamento (
    iditem INT PRIMARY KEY,
    processado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (iditem) REFERENCES item(iditem) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE solicitacao (
    idsolicitacao INT PRIMARY KEY AUTO_INCREMENT,
    item_iditem INT NOT NULL,
    usuario_idusuario INT NOT NULL,
    datarequisicao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('pendente','aceito','reservado','aguardando_entrega','em_processo','entregue','cancelado') DEFAULT 'pendente',
    FOREIGN KEY (item_iditem) REFERENCES item(iditem) ON DELETE CASCADE,
    FOREIGN KEY (usuario_idusuario) REFERENCES usuario(idusuario) ON DELETE CASCADE,
    KEY idx_item_iditem (item_iditem),
    KEY idx_usuario_idusuario (usuario_idusuario),
    KEY idx_status (status),
    UNIQUE KEY unique_solicitacao (item_iditem, usuario_idusuario)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE mensagem (
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

CREATE TABLE avaliacao (
    idavaliacao INT PRIMARY KEY AUTO_INCREMENT,
    idusuario_avaliador INT NOT NULL,
    idusuario_avaliado INT NOT NULL,
    avaliacao INT CHECK (avaliacao >= 1 AND avaliacao <= 5),
    comentario TEXT,
    dataavaliacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (idusuario_avaliador) REFERENCES usuario(idusuario) ON DELETE CASCADE,
    FOREIGN KEY (idusuario_avaliado) REFERENCES usuario(idusuario) ON DELETE CASCADE,
    KEY idx_avaliado (idusuario_avaliado),
    UNIQUE KEY unique_avaliacao (idusuario_avaliador, idusuario_avaliado)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_sol_status_data ON solicitacao(status, datarequisicao);
CREATE INDEX idx_item_coords ON item(latitude, longitude);
CREATE INDEX idx_usuario_coords ON usuario(latitude, longitude);
