#!/usr/bin/env python3
"""Script de teste para verificar conexão com o banco de dados"""

import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

load_dotenv()

print("=" * 60)
print("TESTE DE CONEXÃO - MARIADB")
print("=" * 60)

# Exibir configurações (senha mascarada)
print(f"\n📋 Configurações:")
print(f"   Host: {os.getenv('DB_HOST')}")
print(f"   User: {os.getenv('DB_USER')}")
print(f"   Password: {'*' * len(os.getenv('DB_PASSWORD', ''))}")
print(f"   Database: {os.getenv('DB_NAME')}")
print(f"   Port: {os.getenv('DB_PORT')}")

# Tentar conectar
try:
    print(f"\n🔗 Conectando ao banco...")
    connection = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME'),
        port=int(os.getenv('DB_PORT')),
        connection_timeout=5,
        charset='utf8mb4',
        collation='utf8mb4_unicode_ci',
        use_unicode=True
    )
    print("   ✅ Conexão estabelecida com sucesso!")
    
    # Testar query simples
    print(f"\n🧪 Testando query simples...")
    cursor = connection.cursor(dictionary=True)
    
    # Health Score
    print(f"\n   → Health Score:")
    query = """
    SELECT
        (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND='Query') AS queries_ativas,
        (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE TIME > 30) AS queries_lentas,
        (SELECT COUNT(*) FROM information_schema.INNODB_TRX) AS transacoes_abertas,
        (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND='Sleep') AS conexoes_sleep
    """
    cursor.execute(query)
    result = cursor.fetchall()
    print(f"     Resultado: {result}")
    
    # Running Queries
    print(f"\n   → Queries em Execução:")
    query = """
    SELECT
        ID AS thread_id,
        USER,
        HOST,
        DB,
        TIME AS segundos_execucao,
        STATE,
        LEFT(INFO, 200) AS query
    FROM information_schema.PROCESSLIST
    WHERE COMMAND = 'Query'
    ORDER BY TIME DESC
    """
    cursor.execute(query)
    result = cursor.fetchall()
    print(f"     Total: {len(result)} queries")
    if result:
        for row in result[:3]:  # Mostrar apenas as 3 primeiras
            print(f"     - {row}")
    else:
        print(f"     (Nenhuma query em execução)")
    
    # Connections
    print(f"\n   → Conexões Ativas:")
    query = """
    SELECT
        COMMAND,
        COUNT(*) AS qtd
    FROM information_schema.PROCESSLIST
    GROUP BY COMMAND
    ORDER BY qtd DESC
    """
    cursor.execute(query)
    result = cursor.fetchall()
    print(f"     Resultado: {result}")
    
    # Locks
    print(f"\n   → Transações Abertas:")
    query = """
    SELECT
        trx_id,
        trx_mysql_thread_id,
        trx_started,
        trx_query
    FROM information_schema.INNODB_TRX
    ORDER BY trx_started
    """
    cursor.execute(query)
    result = cursor.fetchall()
    print(f"     Total: {len(result)} transações")
    if result:
        for row in result[:3]:
            print(f"     - {row}")
    
    # Heavy Queries
    print(f"\n   → Heavy Queries:")
    query = """
    SELECT
        DIGEST_TEXT,
        COUNT_STAR AS execucoes,
        ROUND(SUM_TIMER_WAIT/1e12,2) AS tempo_total_seg,
        ROUND(AVG_TIMER_WAIT/1e9,2) AS tempo_medio_ms
    FROM performance_schema.events_statements_summary_by_digest
    ORDER BY tempo_total_seg DESC
    LIMIT 5
    """
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        print(f"     Total: {len(result)} queries pesadas")
        if result:
            for row in result:
                print(f"     - {row}")
    except Error as e:
        print(f"     ⚠️  Performance schema pode não estar habilitado: {e}")
    
    cursor.close()
    connection.close()
    
    print(f"\n✅ TESTE CONCLUÍDO COM SUCESSO!")
    print("=" * 60)
    
except Error as e:
    print(f"\n❌ ERRO ao conectar: {e}")
    print(f"\nVerifique:")
    print(f"  - Se o MariaDB/MySQL está rodando")
    print(f"  - Se as credenciais estão corretas")
    print(f"  - Se o host é acessível")
    print("=" * 60)
except Exception as e:
    print(f"\n❌ ERRO INESPERADO: {e}")
    print("=" * 60)
