-- ==============================================================
-- Setup do Schema DEVOPS para Monitoramento de Performance
-- ==============================================================

-- Criar schema se não existir
CREATE SCHEMA IF NOT EXISTS devops;

-- Tabela para armazenar histórico de métricas gerais
CREATE TABLE IF NOT EXISTS devops.metric_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    -- Conexões
    total_connections INT,
    active_queries INT,
    slow_queries INT,
    sleeping_connections INT,
    
    -- Performance
    qps DECIMAL(10, 2),
    avg_query_time DECIMAL(10, 4),
    
    -- Buffer Pool
    buffer_pool_used_pct DECIMAL(5, 2),
    innodb_reads INT,
    innodb_writes INT,
    
    -- Locks
    open_locks INT,
    open_transactions INT,
    
    -- Índices
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para armazenar histórico de queries lentas
CREATE TABLE IF NOT EXISTS devops.slow_query_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    query_hash VARCHAR(64),
    query_text LONGTEXT,
    execution_time DECIMAL(10, 2),
    user VARCHAR(100),
    database_name VARCHAR(100),
    lock_time DECIMAL(10, 4),
    rows_examined BIGINT,
    rows_sent BIGINT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_database (database_name),
    INDEX idx_execution_time (execution_time),
    UNIQUE KEY unique_query_time (query_hash, timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para armazenar histórico de conexões
CREATE TABLE IF NOT EXISTS devops.connection_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    total_connections INT,
    active_queries INT,
    idle_connections INT,
    waiting_queries INT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para armazenar histórico de tamanho de tabelas
CREATE TABLE IF NOT EXISTS devops.table_size_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    table_schema VARCHAR(100),
    table_name VARCHAR(100),
    table_size_mb DECIMAL(10, 2),
    index_size_mb DECIMAL(10, 2),
    total_size_mb DECIMAL(10, 2),
    row_count BIGINT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_table (table_schema, table_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela para armazenar histórico de QPS (Queries Per Second)
CREATE TABLE IF NOT EXISTS devops.qps_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    queries_total BIGINT,
    selects INT,
    inserts INT,
    updates INT,
    deletes INT,
    qps DECIMAL(10, 2),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Política de limpeza automática: manter apenas 7 dias de histórico
-- (executar este comando regularmente, ou criar uma trigger/event)
-- DELETE FROM devops.metric_history WHERE timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY);
-- DELETE FROM devops.slow_query_history WHERE timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY);
-- DELETE FROM devops.connection_history WHERE timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY);
-- DELETE FROM devops.table_size_history WHERE timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY);
-- DELETE FROM devops.qps_history WHERE timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY);

-- Exibir estrutura das tabelas criadas
SHOW TABLES IN devops;
