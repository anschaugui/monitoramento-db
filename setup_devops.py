#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script para criar o schema devops e suas tabelas de histórico
"""

import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    'host': os.getenv('SETUP_DB_HOST', os.getenv('DB_HOST')),
    'user': os.getenv('SETUP_DB_USER', os.getenv('DB_USER')),
    'password': os.getenv('SETUP_DB_PASSWORD', os.getenv('DB_PASSWORD')),
    'database': 'mysql',
    'port': int(os.getenv('SETUP_DB_PORT', os.getenv('DB_PORT'))),
    'connection_timeout': 10,
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_unicode_ci',
}

SQL_COMMANDS = [
    # Criar schema
    "CREATE SCHEMA IF NOT EXISTS devops;",
    
    # Tabela de histórico de métricas gerais
    """CREATE TABLE IF NOT EXISTS devops.metric_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        total_connections INT,
        active_queries INT,
        slow_queries INT,
        sleeping_connections INT,
        qps DECIMAL(10, 2),
        avg_query_time DECIMAL(10, 4),
        buffer_pool_used_pct DECIMAL(5, 2),
        innodb_reads INT,
        innodb_writes INT,
        open_locks INT,
        open_transactions INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_timestamp (timestamp)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;""",
    
    # Tabela de histórico de queries lentas
    """CREATE TABLE IF NOT EXISTS devops.slow_query_history (
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
        INDEX idx_execution_time (execution_time)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;""",
    
    # Tabela de histórico de conexões
    """CREATE TABLE IF NOT EXISTS devops.connection_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        total_connections INT,
        active_queries INT,
        idle_connections INT,
        waiting_queries INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_timestamp (timestamp)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;""",
    
    # Tabela de histórico de tamanho de tabelas
    """CREATE TABLE IF NOT EXISTS devops.table_size_history (
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
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;""",
    
    # Tabela de histórico de QPS
    """CREATE TABLE IF NOT EXISTS devops.qps_history (
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
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;"""
]

def create_devops_schema():
    """Cria o schema devops e suas tabelas"""
    connection = None
    cursor = None
    
    try:
        print("🔌 Conectando ao banco de dados...")
        connection = mysql.connector.connect(**DB_CONFIG)
        cursor = connection.cursor()
        
        for i, sql in enumerate(SQL_COMMANDS, 1):
            print(f"⚡ Executando comando {i}/{len(SQL_COMMANDS)}...", end=" ")
            try:
                cursor.execute(sql)
                connection.commit()
                print("✅")
            except Error as e:
                print(f"⚠️ (Ignorado: {str(e)[:50]})")
        
        print("\n✅ Schema DEVOPS criado com sucesso!")
        
        # Verificar tabelas criadas
        cursor.execute("SHOW TABLES IN devops;")
        tables = cursor.fetchall()
        print(f"\n📊 Tabelas criadas:")
        for table in tables:
            print(f"   - {table[0]}")
        
    except Error as e:
        print(f"\n❌ Erro: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
    
    return True

if __name__ == '__main__':
    print("=" * 60)
    print("🗄️  SETUP DO SCHEMA DEVOPS - HISTÓRICO DE PERFORMANCE")
    print("=" * 60)
    
    if create_devops_schema():
        print("\n✨ Pronto para receber histórico de métricas!")
    else:
        print("\n❌ Erro durante a criação do schema")
