-- =====================================================
-- Doe Fácil — Script de atualização para bancos
-- criados antes da versão atual.
-- Execute uma vez no seu banco:
--   mysql -u root -p dbdoefacil < backend/migration_fix.sql
-- =====================================================

-- Corrigir ENUM da coluna status em solicitacao
-- (adiciona 'aguardando_entrega' e outros valores que podem estar faltando)
ALTER TABLE solicitacao
    MODIFY COLUMN status ENUM(
        'pendente',
        'aceito',
        'reservado',
        'aguardando_entrega',
        'em_processo',
        'entregue',
        'cancelado'
    ) DEFAULT 'pendente';

-- Adicionar coluna `lida` na tabela mensagem (necessário para badge de não lidas)
ALTER TABLE mensagem ADD COLUMN IF NOT EXISTS lida BOOLEAN DEFAULT FALSE;

-- Adicionar coluna `limite_fila` na tabela item (necessário para controle de fila)
ALTER TABLE item ADD COLUMN IF NOT EXISTS limite_fila INT DEFAULT 10;

-- Adicionar coluna `imagem_url` na tabela item
ALTER TABLE item ADD COLUMN IF NOT EXISTS imagem_url VARCHAR(2048) DEFAULT NULL;

-- Adicionar coluna `prazo_dias` na tabela item (se não existir)
ALTER TABLE item ADD COLUMN IF NOT EXISTS prazo_dias INT DEFAULT 7;

-- Adicionar coluna `dtcriacao` na tabela item (se não existir)
ALTER TABLE item ADD COLUMN IF NOT EXISTS dtcriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Verificar resultado
SELECT 'mensagem.lida' AS coluna, COUNT(*) AS existe
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'mensagem' AND COLUMN_NAME = 'lida'
UNION ALL
SELECT 'item.limite_fila', COUNT(*)
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'item' AND COLUMN_NAME = 'limite_fila'
UNION ALL
SELECT 'item.imagem_url', COUNT(*)
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'item' AND COLUMN_NAME = 'imagem_url';
