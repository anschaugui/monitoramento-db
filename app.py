from flask import Flask, render_template, jsonify, request, Response
import mysql.connector
from mysql.connector import Error, pooling
import os
import re
import time
import threading
import logging
import importlib
import smtplib
from email.message import EmailMessage
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

LOG_LEVEL = os.getenv('APP_LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger('monitoramento-db')

app = Flask(__name__)


def env_int(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


APP_HOST = os.getenv('APP_HOST', '0.0.0.0')
APP_PORT = env_int('APP_PORT', 9001)
APP_DEBUG = env_bool('APP_DEBUG', False)
COLLECTOR_ENABLED = env_bool('COLLECTOR_ENABLED', True)
COLLECTOR_INTERVAL_SECONDS = max(30, env_int('COLLECTOR_INTERVAL_SECONDS', 300))
COLLECT_MIN_INTERVAL_SECONDS = max(15, env_int('COLLECT_MIN_INTERVAL_SECONDS', 60))
RETENTION_CLEANUP_INTERVAL_SECONDS = max(300, env_int('RETENTION_CLEANUP_INTERVAL_SECONDS', 3600))
USE_WAITRESS = env_bool('USE_WAITRESS', True)
WAITRESS_THREADS = max(2, env_int('WAITRESS_THREADS', 8))
DB_USE_POOL = env_bool('DB_USE_POOL', True)
DB_POOL_SIZE = max(3, env_int('DB_POOL_SIZE', 10))
SETUP_DB_POOL_SIZE = max(2, env_int('SETUP_DB_POOL_SIZE', 5))

ALERT_EMAIL_ENABLED = env_bool('ALERT_EMAIL_ENABLED', False)
ALERT_SMTP_HOST = os.getenv('ALERT_SMTP_HOST', '')
ALERT_SMTP_PORT = env_int('ALERT_SMTP_PORT', 587)
ALERT_SMTP_USER = os.getenv('ALERT_SMTP_USER', '')
ALERT_SMTP_PASSWORD = os.getenv('ALERT_SMTP_PASSWORD', '')
ALERT_SMTP_USE_TLS = env_bool('ALERT_SMTP_USE_TLS', True)
ALERT_EMAIL_FROM = os.getenv('ALERT_EMAIL_FROM', ALERT_SMTP_USER or 'monitoramento-db@localhost')
ALERT_EMAIL_TO = [item.strip() for item in os.getenv('ALERT_EMAIL_TO', '').split(',') if item.strip()]
ALERT_EMAIL_SUBJECT_PREFIX = os.getenv('ALERT_EMAIL_SUBJECT_PREFIX', '[DBA Monitor]')
ALERT_COOLDOWN_SECONDS = max(60, env_int('ALERT_COOLDOWN_SECONDS', 900))
ALERT_SLOW_QUERIES_CRITICAL_THRESHOLD = max(5, env_int('ALERT_SLOW_QUERIES_CRITICAL_THRESHOLD', 20))
ALERT_OPEN_LOCKS_CRITICAL_THRESHOLD = max(5, env_int('ALERT_OPEN_LOCKS_CRITICAL_THRESHOLD', 20))
ALERT_CONNECTION_RATIO_CRITICAL_THRESHOLD = max(80, env_int('ALERT_CONNECTION_RATIO_CRITICAL_THRESHOLD', 98))
ALERT_REPLICA_LAG_CRITICAL_SECONDS = max(60, env_int('ALERT_REPLICA_LAG_CRITICAL_SECONDS', 300))
ALERT_MIN_CONSECUTIVE_OBSERVATIONS = max(1, env_int('ALERT_MIN_CONSECUTIVE_OBSERVATIONS', 3))
ALERT_MIN_INCIDENT_AGE_SECONDS = max(0, env_int('ALERT_MIN_INCIDENT_AGE_SECONDS', 180))
ALERT_MIN_CRITICAL_INCIDENTS_TO_NOTIFY = max(1, env_int('ALERT_MIN_CRITICAL_INCIDENTS_TO_NOTIFY', 2))
ALERT_MAX_EMAILS_PER_HOUR = max(1, env_int('ALERT_MAX_EMAILS_PER_HOUR', 3))

AUTH_USER = os.getenv('AUTH_USER')
AUTH_PASSWORD = os.getenv('AUTH_PASSWORD')
AUTH_ENABLED = bool(AUTH_USER and AUTH_PASSWORD)

_collector_thread = None
_collector_stop_event = threading.Event()
_collect_lock = threading.Lock()
_last_collect_at = 0.0
_last_retention_cleanup_at = 0.0
_pool_lock = threading.Lock()
_db_pool = None
_devops_pool = None
_alert_state_lock = threading.Lock()
_last_alert_sent_by_key = {}
_incident_observation_state = {}
_alert_send_history = []
_replica_flow_state = {
    'last_read_pos': None,
    'last_exec_pos': None,
    'last_read_progress_at': None,
    'last_exec_progress_at': None
}
REPLICA_FLOW_TIMEOUT_SECONDS = max(30, env_int('REPLICA_FLOW_TIMEOUT_SECONDS', 90))

# Configurações de segurança
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'port': env_int('DB_PORT', 3306),
    'connection_timeout': 5,
    'autocommit': True,  # Apenas leitura, sem transações
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_unicode_ci',  # Compatível com MariaDB
    'use_unicode': True
}

def validate_select_only(query):
    """Valida se a query é apenas leitura (SELECT, SHOW, etc)"""
    # Remove comentários e espaços em branco
    cleaned_query = re.sub(r'--.*', '', query)
    cleaned_query = re.sub(r'/\*.*?\*/', '', cleaned_query, flags=re.DOTALL)
    cleaned_query = cleaned_query.strip()
    
    # Verifica se é comando de leitura permitido (SELECT, SHOW, DESC, DESCRIBE, EXPLAIN)
    allowed_read_commands = [r'^\s*SELECT\s', r'^\s*SHOW\s', r'^\s*DESC\s', r'^\s*DESCRIBE\s', r'^\s*EXPLAIN\s']
    is_read_command = any(re.match(pattern, cleaned_query, re.IGNORECASE) for pattern in allowed_read_commands)
    
    if not is_read_command:
        raise ValueError("Apenas comandos de leitura (SELECT, SHOW, DESC, DESCRIBE, EXPLAIN) são permitidos!")
    
    # Bloqueia escrita em statements adicionais após ';'
    forbidden_after_semicolon = [r'INSERT', r'UPDATE', r'DELETE', r'DROP', r'CREATE', r'ALTER',
                                r'TRUNCATE', r'GRANT', r'REVOKE', r'REPLACE']
    
    upper_query = cleaned_query.upper()
    for cmd in forbidden_after_semicolon:
        if re.search(rf';\s*{cmd}\b', upper_query):
            raise ValueError(f"Comando não permitido detectado após ';': {cmd}")

    # Bloqueia exportação de dados por SELECT ... INTO OUTFILE
    if re.search(r'\bINTO\s+OUTFILE\b', upper_query):
        raise ValueError("Comando não permitido detectado: INTO OUTFILE")
    
    return True

def get_db_connection():
    """Cria conexão com o banco de dados com timeout"""
    global _db_pool
    connection = None
    try:
        if DB_USE_POOL:
            if _db_pool is None:
                with _pool_lock:
                    if _db_pool is None:
                        _db_pool = pooling.MySQLConnectionPool(
                            pool_name='monitor_read_pool',
                            pool_size=DB_POOL_SIZE,
                            **DB_CONFIG
                        )
            return _db_pool.get_connection()

        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        logger.error(f"Falha ao conectar ao banco: {e}")
        if connection:
            try:
                connection.close()
            except:
                pass
        return None

def execute_query(query):
    """Executa uma query SELECT e retorna os resultados"""
    connection = None
    cursor = None
    
    try:
        # Validar query
        validate_select_only(query)
        
        # Conectar ao banco
        connection = get_db_connection()
        if not connection:
            return None
        
        # Executar query
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query)
        results = cursor.fetchall()
        
        return results
        
    except ValueError as e:
        logger.warning(f"Tentativa de query inválida: {e}")
        return None
    except Error as e:
        logger.error(f"Falha ao executar query: {e}")
        return None
    finally:
        # Garantir fechamento dos recursos
        if cursor:
            try:
                cursor.close()
            except:
                pass
        if connection:
            try:
                connection.close()
            except:
                pass

def get_devops_connection():
    """Conexão para escrita no schema devops usando credenciais de setup, se disponíveis"""
    global _devops_pool
    connection = None
    try:
        config = {
            'host': os.getenv('SETUP_DB_HOST', os.getenv('DB_HOST')),
            'user': os.getenv('SETUP_DB_USER', os.getenv('DB_USER')),
            'password': os.getenv('SETUP_DB_PASSWORD', os.getenv('DB_PASSWORD')),
            'port': env_int('SETUP_DB_PORT', env_int('DB_PORT', 3306)),
            'database': 'devops',
            'connection_timeout': 10,
            'autocommit': False,
            'charset': 'utf8mb4',
            'collation': 'utf8mb4_unicode_ci',
            'use_unicode': True
        }

        if DB_USE_POOL:
            if _devops_pool is None:
                with _pool_lock:
                    if _devops_pool is None:
                        _devops_pool = pooling.MySQLConnectionPool(
                            pool_name='monitor_devops_pool',
                            pool_size=SETUP_DB_POOL_SIZE,
                            **config
                        )
            return _devops_pool.get_connection()

        connection = mysql.connector.connect(**config)
        return connection
    except Error as e:
        logger.error(f"Falha ao conectar no schema devops: {e}")
        if connection:
            try:
                connection.close()
            except:
                pass
        return None

def execute_write(query, params=None):
    """Executa comando de escrita no schema devops"""
    connection = None
    cursor = None
    try:
        connection = get_devops_connection()
        if not connection:
            return False

        cursor = connection.cursor()
        cursor.execute(query, params or ())
        connection.commit()
        return True
    except Error as e:
        logger.error(f"Falha ao executar escrita: {e}")
        if connection:
            try:
                connection.rollback()
            except:
                pass
        return False
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass
        if connection:
            try:
                connection.close()
            except:
                pass

def ensure_devops_tables():
    """Garante que estruturas auxiliares de monitoramento existam no schema devops"""
    execute_write(
        """
        CREATE TABLE IF NOT EXISTS devops.dba_signal_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            replication_lag_seconds INT,
            replication_running TINYINT(1),
            deadlocks_total BIGINT,
            tmp_disk_tables_total BIGINT,
            threads_running INT,
            buffer_pool_hit_ratio DECIMAL(8,4),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_timestamp (timestamp)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )

def parse_status_map(rows):
    """Converte retorno de SHOW STATUS para dicionário"""
    status_map = {}
    if rows:
        for row in rows:
            key = row.get('Variable_name') or row.get('variable_name')
            value = row.get('Value') or row.get('value')
            if key:
                status_map[key] = value
    return status_map


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_runtime_health_snapshot():
    """Coleta métricas operacionais base para endpoints de saúde/IA."""
    health = execute_query("""
        SELECT
            (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND='Query') AS active_queries,
            (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE TIME > 30) AS slow_queries,
            (SELECT COUNT(*) FROM information_schema.INNODB_TRX) AS open_locks,
            (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND='Sleep') AS sleep_connections,
            (SELECT COUNT(*) FROM information_schema.PROCESSLIST) AS total_connections,
            (SELECT @@innodb_buffer_pool_size / 1024 / 1024 / 1024) AS buffer_pool_gb,
            (SELECT @@max_connections) AS max_connections
    """)

    if not health:
        return None

    h = health[0]
    max_connections = max(1, _safe_int(h.get('max_connections'), 100))
    total_connections = _safe_int(h.get('total_connections'), 0)

    return {
        'active_queries': _safe_int(h.get('active_queries'), 0),
        'slow_queries': _safe_int(h.get('slow_queries'), 0),
        'open_locks': _safe_int(h.get('open_locks'), 0),
        'sleep_connections': _safe_int(h.get('sleep_connections'), 0),
        'total_connections': total_connections,
        'buffer_pool_gb': float(h.get('buffer_pool_gb') or 0),
        'max_connections': max_connections,
        'connection_ratio_pct': (total_connections / max_connections) * 100
    }


def _email_config_status():
    missing = []
    if not ALERT_SMTP_HOST:
        missing.append('ALERT_SMTP_HOST')
    if not ALERT_EMAIL_TO:
        missing.append('ALERT_EMAIL_TO')
    if not ALERT_EMAIL_FROM:
        missing.append('ALERT_EMAIL_FROM')
    if ALERT_SMTP_USER and not ALERT_SMTP_PASSWORD:
        missing.append('ALERT_SMTP_PASSWORD')

    configured = len(missing) == 0
    return {
        'enabled': ALERT_EMAIL_ENABLED,
        'configured': configured,
        'smtp_host': ALERT_SMTP_HOST,
        'smtp_port': ALERT_SMTP_PORT,
        'use_tls': ALERT_SMTP_USE_TLS,
        'from': ALERT_EMAIL_FROM,
        'to': ALERT_EMAIL_TO,
        'cooldown_seconds': ALERT_COOLDOWN_SECONDS,
        'policy': {
            'slow_queries_critical_threshold': ALERT_SLOW_QUERIES_CRITICAL_THRESHOLD,
            'open_locks_critical_threshold': ALERT_OPEN_LOCKS_CRITICAL_THRESHOLD,
            'connection_ratio_critical_threshold': ALERT_CONNECTION_RATIO_CRITICAL_THRESHOLD,
            'replica_lag_critical_seconds': ALERT_REPLICA_LAG_CRITICAL_SECONDS,
            'min_consecutive_observations': ALERT_MIN_CONSECUTIVE_OBSERVATIONS,
            'min_incident_age_seconds': ALERT_MIN_INCIDENT_AGE_SECONDS,
            'min_critical_incidents_to_notify': ALERT_MIN_CRITICAL_INCIDENTS_TO_NOTIFY,
            'max_emails_per_hour': ALERT_MAX_EMAILS_PER_HOUR
        },
        'missing': missing
    }


def _build_management_incidents():
    incidents = []
    snapshot = get_runtime_health_snapshot()

    if snapshot:
        if snapshot['slow_queries'] >= ALERT_SLOW_QUERIES_CRITICAL_THRESHOLD:
            incidents.append({
                'key': 'slow_queries_critical',
                'severity': 'CRÍTICO',
                'title': 'Volume crítico de queries lentas',
                'detail': f"{snapshot['slow_queries']} queries acima de 30s em execução",
                'action': 'Priorizar EXPLAIN e redução de concorrência nas queries críticas',
                'command': 'SELECT ID, TIME, STATE, INFO FROM information_schema.PROCESSLIST WHERE TIME > 30 ORDER BY TIME DESC;'
            })

        if snapshot['open_locks'] >= ALERT_OPEN_LOCKS_CRITICAL_THRESHOLD:
            incidents.append({
                'key': 'open_locks_critical',
                'severity': 'CRÍTICO',
                'title': 'Contenção crítica por locks',
                'detail': f"{snapshot['open_locks']} transações abertas/locks ativos",
                'action': 'Investigar sessões bloqueantes e reduzir transações longas',
                'command': 'SHOW ENGINE INNODB STATUS\\G'
            })

        if snapshot['connection_ratio_pct'] >= ALERT_CONNECTION_RATIO_CRITICAL_THRESHOLD:
            incidents.append({
                'key': 'connections_critical',
                'severity': 'CRÍTICO',
                'title': 'Saturação de conexões',
                'detail': f"Uso de conexões em {snapshot['connection_ratio_pct']:.1f}%",
                'action': 'Verificar pool da aplicação e limite de max_connections',
                'command': 'SHOW STATUS LIKE "Threads_connected";'
            })

    replica_status = execute_query("SHOW SLAVE STATUS") or []
    if replica_status:
        rs = replica_status[0]
        io_running = rs.get('Slave_IO_Running') == 'Yes'
        sql_running = rs.get('Slave_SQL_Running') == 'Yes'
        lag_seconds = _safe_int(rs.get('Seconds_Behind_Master'), 0)
        last_error = rs.get('Last_Error', '') or rs.get('Last_SQL_Error', '')

        if (not io_running) or (not sql_running):
            incidents.append({
                'key': 'replica_down',
                'severity': 'CRÍTICO',
                'title': 'Queda de replicação detectada',
                'detail': 'Threads de replicação (IO/SQL) não estão saudáveis',
                'action': 'Revisar erro e reiniciar a replicação após correção',
                'command': 'SHOW SLAVE STATUS\\G'
            })

        if lag_seconds >= ALERT_REPLICA_LAG_CRITICAL_SECONDS:
            incidents.append({
                'key': 'replica_lag_critical',
                'severity': 'CRÍTICO',
                'title': 'Lag crítico de replicação',
                'detail': f'Replicação atrasada em {lag_seconds}s',
                'action': 'Reduzir carga de escrita no master e investigar gargalos no replica',
                'command': 'SHOW PROCESSLIST;'
            })

        if last_error:
            incidents.append({
                'key': 'replica_last_error',
                'severity': 'CRÍTICO',
                'title': 'Erro ativo na réplica',
                'detail': last_error[:180],
                'action': 'Corrigir erro SQL e retomar aplicação de eventos',
                'command': 'SHOW SLAVE STATUS\\G'
            })

    severity_order = {'CRÍTICO': 0, 'ALTO': 1, 'MÉDIO': 2, 'INFO': 3}
    incidents = sorted(incidents, key=lambda item: severity_order.get(item.get('severity', 'INFO'), 99))
    return incidents


def _select_incidents_for_dispatch(incidents, force=False):
    now_ts = time.time()
    critical_incidents = [item for item in incidents if item.get('severity') == 'CRÍTICO']
    if not critical_incidents:
        return [], 'Nenhum incidente crítico para envio'

    immediate_keys = {'replica_down', 'replica_last_error'}
    qualified = []

    with _alert_state_lock:
        active_keys = set()
        for item in critical_incidents:
            key = item.get('key') or item.get('title')
            active_keys.add(key)
            state = _incident_observation_state.get(key)

            if not state:
                state = {
                    'first_seen_at': now_ts,
                    'last_seen_at': now_ts,
                    'consecutive_observations': 1
                }
            else:
                if (now_ts - state.get('last_seen_at', 0)) <= 180:
                    state['consecutive_observations'] = int(state.get('consecutive_observations', 0)) + 1
                else:
                    state['first_seen_at'] = now_ts
                    state['consecutive_observations'] = 1
                state['last_seen_at'] = now_ts

            _incident_observation_state[key] = state

            age_seconds = int(max(0, now_ts - state.get('first_seen_at', now_ts)))
            streak = int(state.get('consecutive_observations', 1))

            is_immediate = key in immediate_keys
            is_persistent = (streak >= ALERT_MIN_CONSECUTIVE_OBSERVATIONS) and (age_seconds >= ALERT_MIN_INCIDENT_AGE_SECONDS)

            if force or is_immediate or is_persistent:
                enriched = dict(item)
                enriched['observation_age_seconds'] = age_seconds
                enriched['consecutive_observations'] = streak
                qualified.append(enriched)

        stale_keys = [k for k, v in _incident_observation_state.items() if (k not in active_keys) and (now_ts - v.get('last_seen_at', 0) > 900)]
        for key in stale_keys:
            _incident_observation_state.pop(key, None)

    if not force:
        non_immediate_count = len([item for item in qualified if item.get('key') not in immediate_keys])
        immediate_count = len([item for item in qualified if item.get('key') in immediate_keys])
        if immediate_count == 0 and non_immediate_count < ALERT_MIN_CRITICAL_INCIDENTS_TO_NOTIFY:
            return [], (
                f"Críticos persistentes insuficientes ({non_immediate_count}/{ALERT_MIN_CRITICAL_INCIDENTS_TO_NOTIFY}); "
                f"aguardando confirmação"
            )

    return qualified, None


def _send_incident_email(incidents, force=False):
    config = _email_config_status()
    if not config['enabled']:
        return {'sent': False, 'skipped': True, 'reason': 'ALERT_EMAIL_ENABLED=false'}

    if not config['configured']:
        return {
            'sent': False,
            'skipped': True,
            'reason': f"Configuração SMTP incompleta: {', '.join(config['missing'])}"
        }

    pending, pending_reason = _select_incidents_for_dispatch(incidents, force=force)
    if not pending:
        return {'sent': False, 'skipped': True, 'reason': pending_reason or 'Nenhum incidente crítico para envio'}

    now_ts = time.time()

    with _alert_state_lock:
        _alert_send_history[:] = [ts for ts in _alert_send_history if now_ts - ts <= 3600]
        if (not force) and len(_alert_send_history) >= ALERT_MAX_EMAILS_PER_HOUR:
            return {
                'sent': False,
                'skipped': True,
                'reason': f'Limite horário atingido ({ALERT_MAX_EMAILS_PER_HOUR} e-mails/h)'
            }

        cooldown_pending = []
        for item in pending:
            key = item.get('key') or item.get('title')
            last_sent_at = _last_alert_sent_by_key.get(key, 0)
            if force or (now_ts - last_sent_at >= ALERT_COOLDOWN_SECONDS):
                cooldown_pending.append(item)

    pending = cooldown_pending

    if not pending:
        return {'sent': False, 'skipped': True, 'reason': 'Cooldown ativo para todos os incidentes críticos'}

    subject = f"{ALERT_EMAIL_SUBJECT_PREFIX} {len(pending)} incidente(s) crítico(s)"
    body_lines = [
        'Incidentes críticos detectados no monitoramento de banco:',
        ''
    ]
    for idx, item in enumerate(pending, start=1):
        body_lines.append(f"{idx}. {item.get('title')}")
        body_lines.append(f"   Detalhe: {item.get('detail')}")
        body_lines.append(f"   Ação: {item.get('action')}")
        if item.get('command'):
            body_lines.append(f"   SQL: {item.get('command')}")
        body_lines.append('')
    body_lines.append(f"Gerado em: {datetime.now().isoformat()}")

    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = ALERT_EMAIL_FROM
    message['To'] = ', '.join(ALERT_EMAIL_TO)
    message.set_content('\n'.join(body_lines))

    try:
        with smtplib.SMTP(ALERT_SMTP_HOST, ALERT_SMTP_PORT, timeout=15) as smtp:
            if ALERT_SMTP_USE_TLS:
                smtp.starttls()
            if ALERT_SMTP_USER:
                smtp.login(ALERT_SMTP_USER, ALERT_SMTP_PASSWORD)
            smtp.send_message(message)

        with _alert_state_lock:
            for item in pending:
                key = item.get('key') or item.get('title')
                _last_alert_sent_by_key[key] = now_ts
            _alert_send_history.append(now_ts)

        return {
            'sent': True,
            'count': len(pending),
            'subject': subject,
            'to': ALERT_EMAIL_TO
        }
    except Exception as e:
        logger.error(f'Falha no envio de e-mail de incidente: {e}')
        return {'sent': False, 'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')


def _is_authorized_request():
    auth = request.authorization
    return bool(auth and auth.username == AUTH_USER and auth.password == AUTH_PASSWORD)


@app.before_request
def require_auth_if_enabled():
    if not AUTH_ENABLED:
        return None

    if _is_authorized_request():
        return None

    if request.path.startswith('/api/'):
        return jsonify({'error': True, 'message': 'Não autorizado'}), 401

    return Response(
        'Autenticação necessária',
        401,
        {'WWW-Authenticate': 'Basic realm="DBA Monitor"'}
    )


def start_background_collector():
    """Inicia coletor contínuo para histórico sem depender de refresh da UI"""
    global _collector_thread

    if not COLLECTOR_ENABLED:
        logger.info('Coletor automático desabilitado (COLLECTOR_ENABLED=false)')
        return

    if _collector_thread and _collector_thread.is_alive():
        return

    def collector_loop():
        logger.info(f"Coletor automático iniciado (intervalo: {COLLECTOR_INTERVAL_SECONDS}s)")
        while not _collector_stop_event.is_set():
            try:
                with app.app_context():
                    collect_performance_snapshot()
            except Exception as e:
                logger.error(f"Falha no coletor automático: {e}")

            if _collector_stop_event.wait(COLLECTOR_INTERVAL_SECONDS):
                break

    _collector_thread = threading.Thread(target=collector_loop, daemon=True)
    _collector_thread.start()

@app.route('/api/health')
def get_health_score():
    """Retorna score de saúde do banco"""
    snapshot = get_runtime_health_snapshot()
    if snapshot:
        response = {
            'queries_ativas': snapshot['active_queries'],
            'queries_lentas': snapshot['slow_queries'],
            'transacoes_abertas': snapshot['open_locks'],
            'conexoes_sleep': snapshot['sleep_connections']
        }
        logger.debug(f"Health Score Result: {response}")
        return jsonify(response)

    logger.error("Nenhum resultado retornado para health score")
    return jsonify({}), 500


def _calculate_operational_score(snapshot):
    """Calcula score operacional consolidado (0-100)."""
    if not snapshot:
        return 0

    def penalty(value, warn, critical, max_penalty):
        if value <= warn:
            return 0
        if value >= critical:
            return max_penalty
        span = max(1, critical - warn)
        return ((value - warn) / span) * max_penalty

    score = 100
    score -= penalty(snapshot['active_queries'], warn=10, critical=60, max_penalty=20)
    score -= penalty(snapshot['slow_queries'], warn=1, critical=12, max_penalty=35)
    score -= penalty(snapshot['open_locks'], warn=2, critical=12, max_penalty=30)
    score -= penalty(snapshot['connection_ratio_pct'], warn=60, critical=95, max_penalty=15)
    return int(max(0, min(100, score)))


@app.route('/api/dba-summary')
def get_dba_summary():
    """Resumo executivo para decisão rápida do DBA."""
    snapshot = get_runtime_health_snapshot()
    if not snapshot:
        return jsonify({}), 500

    score = _calculate_operational_score(snapshot)

    if score < 50:
        level = 'CRÍTICO'
    elif score < 75:
        level = 'ATENÇÃO'
    else:
        level = 'ESTÁVEL'

    primary_action = 'Sem ação imediata'
    if snapshot['slow_queries'] >= 3:
        primary_action = 'Priorizar análise das queries lentas com EXPLAIN'
    elif snapshot['open_locks'] >= 5:
        primary_action = 'Investigar e reduzir transações longas/locks'
    elif snapshot['connection_ratio_pct'] >= 80:
        primary_action = 'Reduzir pressão de conexões e revisar pool da aplicação'

    return jsonify({
        'ok': True,
        'score': score,
        'level': level,
        'primary_action': primary_action,
        'metrics': {
            'slow_queries': snapshot['slow_queries'],
            'open_locks': snapshot['open_locks'],
            'active_queries': snapshot['active_queries'],
            'connection_ratio_pct': round(snapshot['connection_ratio_pct'], 1),
            'buffer_pool_gb': round(snapshot['buffer_pool_gb'], 2)
        }
    })

@app.route('/api/running-queries')
def get_running_queries():
    """Retorna TOP de queries em execução"""
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
    result = execute_query(query)
    if not result:
        return jsonify([])

    enriched = []
    for row in result:
        segundos_execucao = int(row.get('segundos_execucao') or 0)
        thread_id = row.get('thread_id')
        state = (row.get('STATE') or '').upper()

        decision_level = 'INFO'
        decision_text = 'Monitorar execução; sem ação imediata.'
        action_command = '--'

        if segundos_execucao >= 120 or 'LOCK' in state or 'WAIT' in state:
            decision_level = 'CRÍTICO'
            decision_text = 'Query potencialmente bloqueante. Validar impacto e considerar encerramento manual.'
            action_command = f'KILL {thread_id}; -- Encerrar sessão' if thread_id else '--'
        elif segundos_execucao >= 60:
            decision_level = 'ALTO'
            decision_text = 'Query longa. Rodar EXPLAIN e, se degradando usuários, considerar KILL manual.'
            action_command = f'KILL {thread_id}; -- Se impacto confirmado' if thread_id else '--'
        elif segundos_execucao >= 30:
            decision_level = 'ATENÇÃO'
            decision_text = 'Tempo elevado. Priorizar análise de índice/plano de execução.'
            action_command = '--'

        enriched.append({
            **row,
            'decision_level': decision_level,
            'decision_text': decision_text,
            'action_command': action_command
        })

    return jsonify(enriched)

@app.route('/api/slow-queries')
def get_slow_queries():
    """Retorna quantidade de queries rodando há muito tempo"""
    query = """
    SELECT
        COUNT(*) AS qtd_queries_lentas
    FROM information_schema.PROCESSLIST
    WHERE COMMAND = 'Query'
      AND TIME > 30
    """
    result = execute_query(query)
    return jsonify(result[0] if result else {})

@app.route('/api/locks')
def get_locks():
    """Retorna monitor de locks"""
    query = """
    SELECT
        trx_id,
        trx_mysql_thread_id,
        trx_started,
        trx_query
    FROM information_schema.INNODB_TRX
    ORDER BY trx_started
    """
    result = execute_query(query)
    if not result:
        return jsonify([])

    enriched = []
    for row in result:
        thread_id = row.get('trx_mysql_thread_id')
        enriched.append({
            **row,
            'decision_text': 'Transação aberta pode bloquear outras. Validar sessão e tempo antes de agir.',
            'action_command': f'KILL {thread_id}; -- Somente se sessão estiver travando o ambiente' if thread_id else '--'
        })

    return jsonify(enriched)

@app.route('/api/connections')
def get_connections():
    """Retorna conexões ativas por tipo"""
    query = """
    SELECT
        COMMAND,
        COUNT(*) AS qtd
    FROM information_schema.PROCESSLIST
    GROUP BY COMMAND
    ORDER BY qtd DESC
    """
    result = execute_query(query)
    return jsonify(result if result else [])

@app.route('/api/heavy-queries')
def get_heavy_queries():
    """Retorna queries mais pesadas"""
    query = """
    SELECT
        DIGEST_TEXT,
        COUNT_STAR AS execucoes,
        ROUND(SUM_TIMER_WAIT/1e12,2) AS tempo_total_seg,
        ROUND(AVG_TIMER_WAIT/1e9,2) AS tempo_medio_ms
    FROM performance_schema.events_statements_summary_by_digest
    ORDER BY tempo_total_seg DESC
    LIMIT 10
    """
    result = execute_query(query)
    return jsonify(result if result else [])

@app.route('/api/cache-info')
def get_cache_info():
    """Retorna informações de cache do buffer pool"""
    cache_info = {}
    
    # Pegar tamanho do buffer pool
    query = """
    SELECT @@innodb_buffer_pool_size / 1024 / 1024 / 1024 AS innodb_buffer_pool_size
    """
    result = execute_query(query)
    if result:
        cache_info['innodb_buffer_pool_size'] = round(result[0]['innodb_buffer_pool_size'], 2)
    
    return jsonify(cache_info)

@app.route('/api/database-size')
def get_database_size():
    """Retorna tamanho de todas as databases"""
    query = """
    SELECT
        TABLE_SCHEMA AS database,
        ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS size_mb
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
    GROUP BY TABLE_SCHEMA
    ORDER BY size_mb DESC
    """
    result = execute_query(query)
    return jsonify(result if result else [])

@app.route('/api/top-users')
def get_top_users():
    """Retorna top usuários por queries em execução"""
    query = """
    SELECT
        USER,
        COUNT(*) AS qtd_queries,
        COUNT(DISTINCT DB) AS databases_count
    FROM information_schema.PROCESSLIST
    WHERE USER IS NOT NULL AND COMMAND != 'Sleep'
    GROUP BY USER
    ORDER BY qtd_queries DESC
    LIMIT 10
    """
    result = execute_query(query)
    return jsonify(result if result else [])

@app.route('/api/table-fragmentation')
def get_table_fragmentation():
    """Retorna tabelas fragmentadas (InnoDB)"""
    query = """
    SELECT
        CONCAT(OBJECT_SCHEMA, '.', OBJECT_NAME) AS table_name,
        ROUND(COUNT_DELETE / COUNT_INSERT * 100, 2) AS fragmentation_percent,
        COUNT_INSERT AS inserts,
        COUNT_DELETE AS deletes
    FROM performance_schema.table_io_waits_summary_by_table
    WHERE OBJECT_SCHEMA NOT IN ('mysql', 'performance_schema', 'information_schema', 'sys')
      AND COUNT_DELETE > 0
    ORDER BY fragmentation_percent DESC
    LIMIT 15
    """
    result = execute_query(query)
    return jsonify(result if result else [])

@app.route('/api/uptime')
def get_uptime():
    """Retorna informações de uptime e variáveis importantes"""
    stats = {}
    
    # Usar SHOW STATUS que é mais compatível com MariaDB
    query = "SHOW STATUS WHERE variable_name IN ('Uptime', 'Threads_connected', 'Questions', 'Slow_queries')"
    result = execute_query(query)
    
    if result:
        for row in result:
            var_name = row.get('Variable_name') or row.get('variable_name')
            var_value = row.get('Value') or row.get('variable_value')
            if var_name and var_value:
                stats[var_name] = var_value
    
    # Se SHOW STATUS não retornou nada, tentar com variáveis de sistema
    if not stats:
        try:
            query2 = """
            SELECT 
                '@@version' as Variable_name, @@version as Value
            UNION ALL
            SELECT 'Threads_connected', CAST(@@max_connections as CHAR)
            """
            result2 = execute_query(query2)
            if result2:
                for row in result2:
                    stats[row['Variable_name']] = row['Value']
        except:
            pass
    
    return jsonify(stats)

@app.route('/api/missing-indexes')
def get_missing_indexes():
    """Retorna potenciais indices que estão faltando"""
    query = """
    SELECT
        CONCAT(OBJECT_SCHEMA, '.', OBJECT_NAME) AS table_name,
        COUNT_STAR AS full_scans,
        COUNT_READ AS reads,
        COUNT_INSERT AS inserts,
        COUNT_UPDATE AS updates,
        COUNT_DELETE AS deletes
    FROM performance_schema.table_io_waits_summary_by_table
    WHERE OBJECT_SCHEMA NOT IN ('mysql', 'performance_schema', 'information_schema', 'sys')
    ORDER BY COUNT_STAR DESC
    LIMIT 10
    """
    result = execute_query(query)
    return jsonify(result if result else [])

@app.route('/api/recommendations')
def get_recommendations():
    """Retorna recomendações inteligentes baseadas na análise do banco"""
    recommendations = []
    
    # 1. Análise de Queries Lentas
    slow_query = execute_query("""
        SELECT COUNT(*) as qtd 
        FROM information_schema.PROCESSLIST 
        WHERE COMMAND = 'Query' AND TIME > 30
    """)
    
    if slow_query and slow_query[0]['qtd'] > 0:
        recommendations.append({
            'id': 'slow_queries',
            'priority': 'CRÍTICO' if slow_query[0]['qtd'] > 3 else 'ALTO',
            'title': f"🐌 {slow_query[0]['qtd']} Queries Lentas em Execução",
            'description': f"Existem {slow_query[0]['qtd']} queries rodando por mais de 30 segundos",
            'impact': 'Afeta performance geral e travamento de usuários',
            'actions': [
                '1. KILL a query com KILL <thread_id> se for óbvia',
                '2. Revisar índices na tabela consultada',
                '3. Otimizar a lógica SQL da query',
                '4. Considerar aumentar innodb_lock_wait_timeout'
            ],
            'command': 'SHOW PROCESSLIST; -- Identificar queries lentas pelo TIME > 30s'
        })
    
    # 2. Análise de Locks/Transações
    locks = execute_query("""
        SELECT COUNT(*) as qtd 
        FROM information_schema.INNODB_TRX
    """)
    
    if locks and locks[0]['qtd'] > 3:
        recommendations.append({
            'id': 'open_locks',
            'priority': 'ALTO',
            'title': f"🔒 {locks[0]['qtd']} Transações Abertas (Locks)",
            'description': f"{locks[0]['qtd']} transações abertas podem estar bloqueando outras",
            'impact': 'Reduz concorrência e velocidade das queries',
            'actions': [
                '1. Investigar com SHOW ENGINE INNODB STATUS',
                '2. Comitar/rollback transações aguardando',
                '3. Reduzir tempo das transações no código',
                '4. Aumentar innodb_autoinc_lock_mode se aplicável'
            ],
            'command': 'SHOW ENGINE INNODB STATUS; -- Investigar locks e transações ativas'
        })
    
    # 3. Análise de Conexões Sleep
    sleep_conns = execute_query("""
        SELECT COUNT(*) as qtd 
        FROM information_schema.PROCESSLIST 
        WHERE COMMAND = 'Sleep'
    """)
    
    if sleep_conns and sleep_conns[0]['qtd'] > 10:
        recommendations.append({
            'id': 'sleep_connections',
            'priority': 'MÉDIO',
            'title': f"😴 {sleep_conns[0]['qtd']} Conexões Inativas (Sleep)",
            'description': f"{sleep_conns[0]['qtd']} conexões em estado sleep consomem memória",
            'impact': 'Consome recursos e reduz limite de conexões disponíveis',
            'actions': [
                '1. Reduzir wait_timeout no mysql config',
                '2. Implementar connection pooling na aplicação',
                '3. Revisar timeout das conexões',
                '4. Definir @@wait_timeout para 300 segundos'
            ],
            'command': 'SET wait_timeout = 300; -- Reduzir timeout para desconectar clientes inativos'
        })
    
    # 4. Análise de Buffer Pool
    buffer_pool = execute_query("""
        SELECT @@innodb_buffer_pool_size / 1024 / 1024 / 1024 as size_gb
    """)
    
    if buffer_pool and buffer_pool[0]['size_gb'] < 4:
        recommendations.append({
            'id': 'small_buffer_pool',
            'priority': 'ALTO',
            'title': f"💾 Buffer Pool Pequeno ({buffer_pool[0]['size_gb']:.1f}GB)",
            'description': f"Buffer pool de apenas {buffer_pool[0]['size_gb']:.1f}GB é insuficiente",
            'impact': 'Mais disk I/O, performance ruim, cache hit baixo',
            'actions': [
                '1. Aumentar innodb_buffer_pool_size para 80% RAM física',
                '2. Usar innodb_buffer_pool_instances = 8 em sistemas grandes',
                '3. Restart necessário após mudança',
                '4. Monitorar cache hit ratio depois da mudança'
            ],
            'command': 'SET GLOBAL innodb_buffer_pool_size = 8589934592; -- 8GB (editar /etc/mysql/my.cnf e restart)'
        })
    
    # 5. Análise de Fragmentação
    fragmentation = execute_query("""
        SELECT COUNT(*) as qtd,
               AVG(fragmentation_percent) as avg_frag
        FROM (
            SELECT ROUND(COUNT_DELETE / GREATEST(COUNT_INSERT, 1) * 100, 2) AS fragmentation_percent
            FROM performance_schema.table_io_waits_summary_by_table
            WHERE OBJECT_SCHEMA NOT IN ('mysql', 'performance_schema', 'information_schema', 'sys')
              AND COUNT_DELETE > 0
        ) t
        WHERE fragmentation_percent > 30
    """)
    
    if fragmentation and fragmentation[0]['qtd'] > 0:
        recommendations.append({
            'id': 'table_fragmentation',
            'priority': 'MÉDIO',
            'title': f"🔨 {fragmentation[0]['qtd']} Tabelas Fragmentadas",
            'description': f"{fragmentation[0]['qtd']} tabelas com >30% fragmentação",
            'impact': 'Maior consumo de disco e I/O, varrições mais lentas',
            'actions': [
                '1. Executar OPTIMIZE TABLE para cada tabela fragmentada',
                '2. Agendar durante horário de baixa atividade',
                '3. Monitorar espaço em disco durante otimização',
                '4. Considerar innodb_file_per_table=ON para novos dados'
            ],
            'command': 'OPTIMIZE TABLE table_name; -- Executar para cada tabela fragmentada'
        })
    
    # 6. Análise de Queries em Simultâneo
    active_queries = execute_query("""
        SELECT COUNT(*) as qtd 
        FROM information_schema.PROCESSLIST 
        WHERE COMMAND = 'Query'
    """)
    
    if active_queries and active_queries[0]['qtd'] > 20:
        recommendations.append({
            'id': 'high_concurrency',
            'priority': 'ALTO',
            'title': f"⚡ Alta Concorrência ({active_queries[0]['qtd']} queries)",
            'description': f"{active_queries[0]['qtd']} queries em execução simultânea",
            'impact': 'Pode ficar crítico se crescer mais, risco de travamentos',
            'actions': [
                '1. Aumentar max_connections se necessário',
                '2. Implementar queue/limit na aplicação',
                '3. Otimizar queries mais lentas',
                '4. Considerar read replicas para distribuir carga'
            ],
            'command': 'SET GLOBAL max_connections = 1000; -- Aumentar limite de conexões permitidas'
        })
    
    # 7. Check de Replicação
    replication = execute_query("SHOW SLAVE STATUS")
    if replication and len(replication) > 0:
        slave_lag = replication[0].get('Seconds_Behind_Master')
        if slave_lag and int(slave_lag) > 10:
            recommendations.append({
                'id': 'replication_lag',
                'priority': 'CRÍTICO' if slave_lag > 60 else 'ALTO',
                'title': f"📡 Atraso de Replicação Elevado ({slave_lag}s)",
                'description': f"Slave está {slave_lag}s atrás do master",
                'impact': 'Dados inconsistentes, reads obsoletos',
                'actions': [
                    '1. Verificar network entre master e slave',
                    '2. Otimizar queries lentas no master',
                    '3. Aumentar replica_max_allowed_packet se necessário',
                    '4. Considerar parallel replication (slave_parallel_workers)'
                ],
                'command': 'SHOW SLAVE STATUS; -- Verificar status da replicação e atraso'
            })
    
    return jsonify(recommendations)

@app.route('/api/health-check-detailed')
def get_detailed_health_check():
    """Retorna health check detalhado com scores individuais"""
    snapshot = get_runtime_health_snapshot()
    if not snapshot:
        return jsonify({'checks': []}), 500

    health_data = {
        'checks': []
    }

    slow_count = snapshot['slow_queries']
    health_data['checks'].append({
        'name': 'Queries Lentas',
        'status': 'OK' if slow_count == 0 else 'CRÍTICO' if slow_count > 3 else 'ATENÇÃO',
        'value': slow_count,
        'score': max(0, 100 - (slow_count * 10))
    })

    lock_count = snapshot['open_locks']
    health_data['checks'].append({
        'name': 'Locks Abertos',
        'status': 'OK' if lock_count <= 2 else 'ATENÇÃO' if lock_count <= 5 else 'CRÍTICO',
        'value': lock_count,
        'score': max(0, 100 - (lock_count * 5))
    })

    conn_count = snapshot['total_connections']
    max_c = snapshot['max_connections']
    conn_ratio = snapshot['connection_ratio_pct']
    health_data['checks'].append({
        'name': 'Fila de Conexões',
        'status': 'OK' if conn_ratio < 50 else 'ATENÇÃO' if conn_ratio < 80 else 'CRÍTICO',
        'value': f"{conn_count}/{max_c}",
        'score': max(0, 100 - conn_ratio)
    })

    buffer_size = snapshot['buffer_pool_gb']
    health_data['checks'].append({
        'name': 'Buffer Pool',
        'status': 'OK' if buffer_size >= 8 else 'ATENÇÃO' if buffer_size >= 4 else 'CRÍTICO',
        'value': f"{buffer_size:.1f}GB",
        'score': min(100, (buffer_size / 8) * 100)
    })
    
    return jsonify(health_data)

@app.route('/api/replication-status')
def get_replication_status():
    """Retorna status do banco (online/offline) e detalhes de replicação"""
    try:
        # 1) Primeiro: saúde do banco (principal)
        base_info = execute_query("""
            SELECT
                @@hostname AS hostname,
                @@version AS version,
                @@port AS port,
                @@read_only AS read_only
        """)

        if not base_info:
            return jsonify({
                'error': True,
                'database_online': False,
                'is_active': False,
                'status': 'INATIVO',
                'message': 'Banco de dados indisponível ou sem resposta'
            }), 500

        uptime_result = execute_query("SHOW STATUS WHERE variable_name IN ('Uptime','Threads_connected')") or []
        uptime_map = {}
        for row in uptime_result:
            key = row.get('Variable_name') or row.get('variable_name')
            val = row.get('Value') or row.get('value')
            if key:
                uptime_map[key] = val

        server_data = base_info[0]

        response = {
            'error': False,
            'database_online': True,
            'is_active': True,
            'status': 'ATIVO',
            'db_hostname': server_data.get('hostname', 'N/A'),
            'db_version': server_data.get('version', 'N/A'),
            'db_port': server_data.get('port', 'N/A'),
            'db_read_only': int(server_data.get('read_only', 0) or 0),
            'uptime_seconds': int(uptime_map.get('Uptime', 0) or 0),
            'threads_connected': int(uptime_map.get('Threads_connected', 0) or 0),
            'replication_configured': False,
            'replication_role': 'none',
            'replication_active': None,
            'lag': 0
        }

        # 2) Complemento: replicação (se houver)
        slave_result = execute_query("SHOW SLAVE STATUS")
        if slave_result and len(slave_result) > 0:
            slave_status = slave_result[0]
            io_running = (slave_status.get('Slave_IO_Running', 'No') == 'Yes')
            sql_running = (slave_status.get('Slave_SQL_Running', 'No') == 'Yes')
            replication_running = io_running and sql_running

            lag_raw = slave_status.get('Seconds_Behind_Master')
            lag = _safe_int(lag_raw, 0) if lag_raw is not None else 0
            last_error = slave_status.get('Last_Error', '') or slave_status.get('Last_SQL_Error', '')

            current_read_pos = _safe_int(slave_status.get('Read_Master_Log_Pos'), 0)
            current_exec_pos = _safe_int(slave_status.get('Exec_Master_Log_Pos'), 0)
            now_ts = time.time()

            prev_read_pos = _replica_flow_state['last_read_pos']
            prev_exec_pos = _replica_flow_state['last_exec_pos']

            if _replica_flow_state['last_read_progress_at'] is None:
                _replica_flow_state['last_read_progress_at'] = now_ts
            if _replica_flow_state['last_exec_progress_at'] is None:
                _replica_flow_state['last_exec_progress_at'] = now_ts

            if prev_read_pos is None or current_read_pos != prev_read_pos:
                _replica_flow_state['last_read_progress_at'] = now_ts
            if prev_exec_pos is None or current_exec_pos != prev_exec_pos:
                _replica_flow_state['last_exec_progress_at'] = now_ts

            _replica_flow_state['last_read_pos'] = current_read_pos
            _replica_flow_state['last_exec_pos'] = current_exec_pos

            no_receive_seconds = int(max(0, now_ts - _replica_flow_state['last_read_progress_at']))
            no_apply_seconds = int(max(0, now_ts - _replica_flow_state['last_exec_progress_at']))

            receiving_ok = no_receive_seconds < REPLICA_FLOW_TIMEOUT_SECONDS
            applying_ok = no_apply_seconds < REPLICA_FLOW_TIMEOUT_SECONDS
            replication_healthy = replication_running and receiving_ok and applying_ok and (not last_error)
            
            replication_status_detail = 'OK'
            if not replication_running:
                replication_status_detail = 'THREADS PARADAS'
            elif not receiving_ok:
                replication_status_detail = 'NÃO RECEBENDO DO MASTER'
            elif not applying_ok:
                replication_status_detail = 'NÃO APLICANDO EVENTOS'
            elif last_error:
                replication_status_detail = f'ERRO: {last_error[:100]}'

            response['replication_active'] = replication_healthy
            response['is_active'] = replication_healthy
            response['status'] = 'ATIVO' if replication_healthy else 'INATIVO'
            response['replication_status_detail'] = replication_status_detail

            response.update({
                'replication_configured': True,
                'replication_role': 'replica',
                'server': slave_status.get('Master_Host', 'N/A'),
                'lag': lag,
                'slave_io_running': slave_status.get('Slave_IO_Running', 'No'),
                'slave_sql_running': slave_status.get('Slave_SQL_Running', 'No'),
                'last_error': last_error,
                'read_master_log_pos': current_read_pos,
                'exec_master_log_pos': current_exec_pos,
                'no_receive_seconds': no_receive_seconds,
                'no_apply_seconds': no_apply_seconds,
                'flow_timeout_seconds': REPLICA_FLOW_TIMEOUT_SECONDS,
                'receiving_ok': receiving_ok,
                'applying_ok': applying_ok
            })
            return jsonify(response)

        master_result = execute_query("SHOW MASTER STATUS")
        if master_result and len(master_result) > 0:
            master_status = master_result[0]

            replica_connections = execute_query("""
                SELECT COUNT(*) AS connected_replicas
                FROM information_schema.PROCESSLIST
                WHERE COMMAND IN ('Binlog Dump', 'Binlog Dump GTID')
            """) or []
            connected_replicas = int(replica_connections[0].get('connected_replicas', 0) or 0) if replica_connections else 0

            response.update({
                'replication_configured': True,
                'replication_role': 'master',
                'replication_active': connected_replicas > 0,
                'connected_replicas': connected_replicas,
                'binlog_file': master_status.get('File', 'N/A'),
                'binlog_position': master_status.get('Position', 'N/A')
            })

        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'error': True,
            'database_online': False,
            'is_active': False,
            'message': f'Erro ao verificar replicação: {str(e)}',
            'status': 'ERRO'
        })

@app.route('/api/slow-queries-detail')
def get_slow_queries_detail():
    """Retorna detalhe das queries lentas em execução com análise"""
    query = """
    SELECT
        ID AS thread_id,
        USER,
        HOST,
        DB,
        TIME AS executando_ha_segundos,
        STATE,
        INFO AS query,
        COMMAND
    FROM information_schema.PROCESSLIST
    WHERE COMMAND = 'Query' AND TIME > 30
    ORDER BY TIME DESC
    """
    result = execute_query(query)
    
    if not result:
        return jsonify([])
    
    # Análise inteligente para cada query
    analyzed = []
    for row in result:
        analysis = {
            'thread_id': row['thread_id'],
            'USER': row['USER'],
            'HOST': row['HOST'],
            'DB': row['DB'],
            'executando_ha_segundos': row['executando_ha_segundos'],
            'STATE': row['STATE'],
            'query': row['query'][:500] if row['query'] else '--',
            'query_full': row['query'],
            'recomendacoes': _analyze_slow_query(row)
        }
        analyzed.append(analysis)
    
    return jsonify(analyzed)

def _analyze_slow_query(query_row):
    """Analisa uma query lenta e retorna recomendações"""
    recs = []
    query_text = (query_row.get('query') or '').upper()
    tempo = query_row.get('executando_ha_segundos', 0)
    
    # Recomendação 1: Se muito lenta (>60s), considere matar
    if tempo > 60:
        recs.append({
            'severity': 'critico',
            'acao': 'KILL_QUERY',
            'titulo': 'Query Crítica',
            'problema': f'Query executando há {tempo}s - muito tempo!',
            'solucao': 'Considere encerrar esta query com KILL QUERY ' + str(query_row.get('thread_id', '')),
            'comando': f"KILL QUERY {query_row.get('thread_id', '')}"
        })
    
    # Recomendação 2: Verificar índices
    if 'JOIN' in query_text or 'WHERE' in query_text:
        recs.append({
            'severity': 'aviso',
            'acao': 'ANALYZE_INDEXES',
            'titulo': 'Análise de Índices',
            'problema': 'Esta query contém JOINs ou cláusulas WHERE',
            'solucao': 'Verifique se há índices nas colunas de JOIN e WHERE',
            'comando': f"EXPLAIN {query_row.get('query_full', '')[:300]}"
        })
    
    # Recomendação 3: Verificar locks
    if 'UPDATE' in query_text or 'DELETE' in query_text:
        recs.append({
            'severity': 'aviso',
            'acao': 'CHECK_LOCKS',
            'titulo': 'Verificar Locks',
            'problema': 'Há operações que podem estar causando locks',
            'solucao': 'Verifique se há transações abertas bloqueando esta query'
        })
    
    # Recomendação 4: Se SELECT simples
    if query_text.startswith('SELECT') and 'JOIN' not in query_text:
        recs.append({
            'severity': 'info',
            'acao': 'MONITOR',
            'titulo': 'Monitorar',
            'problema': 'Query simples, mas ainda lenta',
            'solucao': 'Pode indicar volume grande de dados - verifique LIMIT'
        })
    
    return recs if recs else [{'severity': 'info', 'titulo': 'Monitorar', 'problema': 'Query lenta', 'solucao': 'Use EXPLAIN para analisar o plano de execução'}]

@app.route('/api/slow-query-explain/<int:thread_id>')
def get_explain_plan(thread_id):
    """Retorna o EXPLAIN de uma query lenta"""
    # Obter a query do PROCESSLIST
    query = """
    SELECT INFO FROM information_schema.PROCESSLIST
    WHERE ID = %s
    """
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        if not connection:
            return jsonify({'error': 'Falha na conexão'}), 500
        
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, (thread_id,))
        result = cursor.fetchone()
        
        if not result or not result['INFO']:
            return jsonify({'error': 'Query não encontrada'}), 404
        
        query_text = result['INFO']
        
        # Executar EXPLAIN
        explain_query = f"EXPLAIN {query_text}"
        cursor.execute(explain_query)
        explain_result = cursor.fetchall()
        
        return jsonify({
            'query': query_text,
            'explain': explain_result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass
        if connection:
            try:
                connection.close()
            except:
                pass

@app.route('/api/performance-collect', methods=['POST'])
def collect_performance_snapshot():
    """Coleta snapshot atual e persiste no schema devops"""
    global _last_collect_at, _last_retention_cleanup_at

    now_ts = time.time()
    elapsed_since_last = now_ts - _last_collect_at
    if elapsed_since_last < COLLECT_MIN_INTERVAL_SECONDS:
        wait_seconds = int(max(1, COLLECT_MIN_INTERVAL_SECONDS - elapsed_since_last))
        return jsonify({
            'ok': True,
            'skipped': True,
            'message': f'Coleta recente; aguardando {wait_seconds}s para novo snapshot',
            'next_collect_in_seconds': wait_seconds
        })

    if not _collect_lock.acquire(blocking=False):
        return jsonify({
            'ok': True,
            'skipped': True,
            'message': 'Coleta já em execução'
        })

    try:
        _last_collect_at = time.time()
        ensure_devops_tables()

        health = execute_query("""
            SELECT
                (SELECT COUNT(*) FROM information_schema.PROCESSLIST) AS total_connections,
                (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND='Query') AS active_queries,
                (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE TIME > 30) AS slow_queries,
                (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND='Sleep') AS sleeping_connections,
                (SELECT COUNT(*) FROM information_schema.INNODB_TRX) AS open_transactions
        """)

        status = execute_query("""
            SHOW STATUS WHERE variable_name IN (
                'Questions',
                'Uptime',
                'Innodb_data_reads',
                'Innodb_data_writes',
                'Innodb_buffer_pool_pages_data',
                'Innodb_buffer_pool_pages_total',
                'Innodb_buffer_pool_read_requests',
                'Innodb_buffer_pool_reads',
                'Innodb_deadlocks',
                'Created_tmp_disk_tables',
                'Threads_running'
            )
        """)

        tables = execute_query("""
            SELECT
                TABLE_SCHEMA,
                TABLE_NAME,
                ROUND(DATA_LENGTH / 1024 / 1024, 2) AS data_mb,
                ROUND(INDEX_LENGTH / 1024 / 1024, 2) AS index_mb,
                ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS total_mb,
                TABLE_ROWS
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys', 'devops')
            ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC
            LIMIT 30
        """)

        if not health:
            return jsonify({'ok': False, 'message': 'Sem dados de health para coleta'}), 500

        health_row = health[0]
        status_map = parse_status_map(status)

        questions_total = int(status_map.get('Questions', 0) or 0)
        uptime = int(status_map.get('Uptime', 0) or 0)
        innodb_reads = int(status_map.get('Innodb_data_reads', 0) or 0)
        innodb_writes = int(status_map.get('Innodb_data_writes', 0) or 0)
        deadlocks_total = int(status_map.get('Innodb_deadlocks', 0) or 0)
        tmp_disk_tables_total = int(status_map.get('Created_tmp_disk_tables', 0) or 0)
        threads_running = int(status_map.get('Threads_running', 0) or 0)
        pages_data = int(status_map.get('Innodb_buffer_pool_pages_data', 0) or 0)
        pages_total = int(status_map.get('Innodb_buffer_pool_pages_total', 0) or 0)
        read_requests = int(status_map.get('Innodb_buffer_pool_read_requests', 0) or 0)
        reads_from_disk = int(status_map.get('Innodb_buffer_pool_reads', 0) or 0)
        buffer_used_pct = round((pages_data / pages_total) * 100, 2) if pages_total > 0 else 0
        buffer_hit_ratio = round((1 - (reads_from_disk / read_requests)) * 100, 4) if read_requests > 0 else 100.0
        avg_qps = round(questions_total / uptime, 2) if uptime > 0 else 0

        replication_status = execute_query("SHOW SLAVE STATUS") or []
        replication_lag = 0
        replication_running = -1
        if replication_status:
            row = replication_status[0]
            replication_lag = int(row.get('Seconds_Behind_Master') or 0)
            replication_running = 1 if (row.get('Slave_IO_Running') == 'Yes' and row.get('Slave_SQL_Running') == 'Yes') else 0

        previous_qps = execute_query("""
            SELECT queries_total, timestamp
            FROM devops.qps_history
            ORDER BY timestamp DESC
            LIMIT 1
        """)

        instant_qps = avg_qps
        if previous_qps:
            prev_questions = int(previous_qps[0].get('queries_total', 0) or 0)
            prev_timestamp = previous_qps[0].get('timestamp')
            current_timestamp = datetime.now()
            if prev_timestamp:
                elapsed = (current_timestamp - prev_timestamp).total_seconds()
                if elapsed > 0:
                    instant_qps = round(max(0, questions_total - prev_questions) / elapsed, 2)

        execute_write(
            """
            INSERT INTO devops.metric_history (
                timestamp, total_connections, active_queries, slow_queries,
                sleeping_connections, qps, avg_query_time,
                buffer_pool_used_pct, innodb_reads, innodb_writes,
                open_locks, open_transactions
            ) VALUES (NOW(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                int(health_row.get('total_connections', 0) or 0),
                int(health_row.get('active_queries', 0) or 0),
                int(health_row.get('slow_queries', 0) or 0),
                int(health_row.get('sleeping_connections', 0) or 0),
                instant_qps,
                0,
                buffer_used_pct,
                innodb_reads,
                innodb_writes,
                int(health_row.get('open_transactions', 0) or 0),
                int(health_row.get('open_transactions', 0) or 0)
            )
        )

        execute_write(
            """
            INSERT INTO devops.connection_history (
                timestamp, total_connections, active_queries, idle_connections, waiting_queries
            ) VALUES (NOW(), %s, %s, %s, %s)
            """,
            (
                int(health_row.get('total_connections', 0) or 0),
                int(health_row.get('active_queries', 0) or 0),
                int(health_row.get('sleeping_connections', 0) or 0),
                int(health_row.get('open_transactions', 0) or 0)
            )
        )

        execute_write(
            """
            INSERT INTO devops.qps_history (
                timestamp, queries_total, selects, inserts, updates, deletes, qps
            ) VALUES (NOW(), %s, 0, 0, 0, 0, %s)
            """,
            (questions_total, instant_qps)
        )

        execute_write(
            """
            INSERT INTO devops.dba_signal_history (
                timestamp, replication_lag_seconds, replication_running,
                deadlocks_total, tmp_disk_tables_total,
                threads_running, buffer_pool_hit_ratio
            ) VALUES (NOW(), %s, %s, %s, %s, %s, %s)
            """,
            (
                replication_lag,
                replication_running,
                deadlocks_total,
                tmp_disk_tables_total,
                threads_running,
                buffer_hit_ratio
            )
        )

        should_collect_sizes = True
        last_size_snapshot = execute_query("""
            SELECT timestamp
            FROM devops.table_size_history
            ORDER BY timestamp DESC
            LIMIT 1
        """)
        if last_size_snapshot:
            last_ts = last_size_snapshot[0].get('timestamp')
            if last_ts:
                delta_sec = (datetime.now() - last_ts).total_seconds()
                should_collect_sizes = delta_sec >= 600

        if tables and should_collect_sizes:
            for table_row in tables:
                execute_write(
                    """
                    INSERT INTO devops.table_size_history (
                        timestamp, table_schema, table_name,
                        table_size_mb, index_size_mb, total_size_mb, row_count
                    ) VALUES (NOW(), %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        table_row.get('TABLE_SCHEMA'),
                        table_row.get('TABLE_NAME'),
                        float(table_row.get('data_mb', 0) or 0),
                        float(table_row.get('index_mb', 0) or 0),
                        float(table_row.get('total_mb', 0) or 0),
                        int(table_row.get('TABLE_ROWS', 0) or 0)
                    )
                )

        retention_elapsed = time.time() - _last_retention_cleanup_at
        if retention_elapsed >= RETENTION_CLEANUP_INTERVAL_SECONDS:
            execute_write("DELETE FROM devops.metric_history WHERE timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY)")
            execute_write("DELETE FROM devops.connection_history WHERE timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY)")
            execute_write("DELETE FROM devops.qps_history WHERE timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY)")
            execute_write("DELETE FROM devops.table_size_history WHERE timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY)")
            execute_write("DELETE FROM devops.dba_signal_history WHERE timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY)")
            _last_retention_cleanup_at = time.time()

        return jsonify({
            'ok': True,
            'message': 'Snapshot coletado com sucesso',
            'snapshot': {
                'active_queries': int(health_row.get('active_queries', 0) or 0),
                'slow_queries': int(health_row.get('slow_queries', 0) or 0),
                'total_connections': int(health_row.get('total_connections', 0) or 0),
                'qps': instant_qps,
                'deadlocks_total': deadlocks_total,
                'buffer_hit_ratio': buffer_hit_ratio,
                'replication_lag': replication_lag
            }
        })
    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)}), 500
    finally:
        _collect_lock.release()

@app.route('/api/performance-24h')
def get_performance_24h():
    """Retorna dados de performance das últimas 24h para os gráficos"""
    try:
        slow_queries_trend = execute_query("""
            SELECT
                DATE_FORMAT(timestamp, '%d/%m %H:%i') AS label,
                AVG(slow_queries) AS value
            FROM devops.metric_history
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i')
            ORDER BY MIN(timestamp)
        """) or []

        active_connections_trend = execute_query("""
            SELECT
                DATE_FORMAT(timestamp, '%d/%m %H:%i') AS label,
                AVG(total_connections) AS total_connections,
                AVG(active_queries) AS active_queries,
                AVG(idle_connections) AS idle_connections
            FROM devops.connection_history
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i')
            ORDER BY MIN(timestamp)
        """) or []

        qps_trend = execute_query("""
            SELECT
                DATE_FORMAT(timestamp, '%d/%m %H:%i') AS label,
                AVG(qps) AS value
            FROM devops.qps_history
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i')
            ORDER BY MIN(timestamp)
        """) or []

        db_growth = execute_query("""
            SELECT
                DATE_FORMAT(timestamp, '%d/%m %H:00') AS label,
                table_schema,
                SUM(total_size_mb) AS total_size_mb
            FROM devops.table_size_history
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY DATE_FORMAT(timestamp, '%Y-%m-%d %H'), table_schema
            ORDER BY MIN(timestamp), table_schema
        """) or []

        dba_signals = execute_query("""
            SELECT
                DATE_FORMAT(timestamp, '%d/%m %H:%i') AS label,
                AVG(replication_lag_seconds) AS replication_lag_seconds,
                AVG(replication_running) AS replication_running,
                MAX(deadlocks_total) AS deadlocks_total,
                MAX(tmp_disk_tables_total) AS tmp_disk_tables_total,
                AVG(threads_running) AS threads_running,
                AVG(buffer_pool_hit_ratio) AS buffer_pool_hit_ratio
            FROM devops.dba_signal_history
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i')
            ORDER BY MIN(timestamp)
        """) or []

        deadlocks_hourly = execute_query("""
            SELECT
                DATE_FORMAT(timestamp, '%d/%m %H:00') AS label,
                GREATEST(MAX(deadlocks_total) - MIN(deadlocks_total), 0) AS deadlocks_delta
            FROM devops.dba_signal_history
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY DATE_FORMAT(timestamp, '%Y-%m-%d %H')
            ORDER BY MIN(timestamp)
        """) or []

        tmp_disk_tables_hourly = execute_query("""
            SELECT
                DATE_FORMAT(timestamp, '%d/%m %H:00') AS label,
                GREATEST(MAX(tmp_disk_tables_total) - MIN(tmp_disk_tables_total), 0) AS tmp_disk_delta
            FROM devops.dba_signal_history
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY DATE_FORMAT(timestamp, '%Y-%m-%d %H')
            ORDER BY MIN(timestamp)
        """) or []

        return jsonify({
            'slow_queries_trend': slow_queries_trend,
            'active_connections_trend': active_connections_trend,
            'qps_trend': qps_trend,
            'db_growth': db_growth,
            'dba_signals': dba_signals,
            'deadlocks_hourly': deadlocks_hourly,
            'tmp_disk_tables_hourly': tmp_disk_tables_hourly
        })
    except Exception as e:
        return jsonify({
            'slow_queries_trend': [],
            'active_connections_trend': [],
            'qps_trend': [],
            'db_growth': [],
            'dba_signals': [],
            'deadlocks_hourly': [],
            'tmp_disk_tables_hourly': [],
            'error': str(e)
        }), 500

@app.route('/api/dba-alerts')
def get_dba_alerts():
    """Retorna alertas priorizados com foco operacional de DBA"""
    alerts = []
    try:
        latest_metric = execute_query("""
            SELECT total_connections, active_queries, slow_queries, qps, open_transactions
            FROM devops.metric_history
            ORDER BY timestamp DESC
            LIMIT 1
        """)

        latest_signal = execute_query("""
            SELECT replication_lag_seconds, replication_running,
                   deadlocks_total, tmp_disk_tables_total,
                   threads_running, buffer_pool_hit_ratio
            FROM devops.dba_signal_history
            ORDER BY timestamp DESC
            LIMIT 1
        """)

        if latest_metric:
            m = latest_metric[0]
            if float(m.get('slow_queries') or 0) >= 3:
                alerts.append({
                    'severity': 'critico',
                    'title': 'Muitas queries lentas ativas',
                    'detail': f"{int(m.get('slow_queries') or 0)} queries acima de 30s",
                    'action': 'Priorizar EXPLAIN e reduzir concorrência nas queries críticas'
                })
            if float(m.get('open_transactions') or 0) >= 5:
                alerts.append({
                    'severity': 'alto',
                    'title': 'Transações abertas elevadas',
                    'detail': f"{int(m.get('open_transactions') or 0)} transações em aberto",
                    'action': 'Investigar locks e sessões sem commit/rollback'
                })

        if latest_signal:
            s = latest_signal[0]
            replication_state = int(float(s.get('replication_running') or -1))
            if replication_state == 0 and (s.get('replication_lag_seconds') is not None):
                alerts.append({
                    'severity': 'critico',
                    'title': 'Replicação parada',
                    'detail': 'Threads IO/SQL não estão saudáveis',
                    'action': 'Verificar SHOW SLAVE STATUS e reprocessar erro da réplica'
                })
            if replication_state >= 0 and float(s.get('replication_lag_seconds') or 0) > 30:
                alerts.append({
                    'severity': 'alto',
                    'title': 'Replication lag elevado',
                    'detail': f"Atraso atual: {int(s.get('replication_lag_seconds') or 0)}s",
                    'action': 'Reduzir carga no master e revisar eventos com maior write rate'
                })
            if float(s.get('buffer_pool_hit_ratio') or 100) < 99:
                alerts.append({
                    'severity': 'medio',
                    'title': 'Buffer pool hit ratio abaixo do ideal',
                    'detail': f"Hit ratio: {float(s.get('buffer_pool_hit_ratio') or 0):.2f}%",
                    'action': 'Ajustar buffer pool e revisar queries com full scan'
                })

        severity_order = {'critico': 0, 'alto': 1, 'medio': 2, 'info': 3}
        alerts = sorted(alerts, key=lambda item: severity_order.get(item.get('severity', 'info'), 99))

        return jsonify(alerts)
    except Exception as e:
        return jsonify([{
            'severity': 'info',
            'title': 'Sem alertas disponíveis',
            'detail': f'Falha ao gerar alertas: {str(e)}',
            'action': 'Verifique conectividade com schema devops'
        }])


@app.route('/api/management/incidents')
def get_management_incidents():
    """Retorna incidentes críticos para aba de gerenciamento."""
    try:
        incidents = _build_management_incidents()
        return jsonify({
            'ok': True,
            'timestamp': datetime.now().isoformat(),
            'incidents': incidents,
            'email': _email_config_status()
        })
    except Exception as e:
        return jsonify({
            'ok': False,
            'incidents': [],
            'email': _email_config_status(),
            'message': str(e)
        }), 500


@app.route('/api/management/dispatch-email', methods=['POST'])
def dispatch_management_email():
    """Envia e-mail com incidentes críticos (com cooldown)."""
    body = request.get_json(silent=True) or {}
    force = bool(body.get('force', False))

    incidents = _build_management_incidents()
    result = _send_incident_email(incidents, force=force)

    status_code = 200
    if result.get('error'):
        status_code = 500

    return jsonify({
        'ok': not bool(result.get('error')),
        'timestamp': datetime.now().isoformat(),
        'incidents_count': len(incidents),
        'dispatch': result
    }), status_code

if __name__ == '__main__':
    should_start_collector = (not APP_DEBUG) or (os.getenv('WERKZEUG_RUN_MAIN') == 'true')
    if should_start_collector:
        start_background_collector()

    if (not APP_DEBUG) and USE_WAITRESS:
        try:
            serve = importlib.import_module('waitress').serve
            logger.info(f"Iniciando servidor Waitress em {APP_HOST}:{APP_PORT} (threads={WAITRESS_THREADS})")
            serve(app, host=APP_HOST, port=APP_PORT, threads=WAITRESS_THREADS)
        except Exception as e:
            logger.warning(f"Falha ao iniciar Waitress ({e}), usando servidor Flask")
            app.run(debug=APP_DEBUG, host=APP_HOST, port=APP_PORT)
    else:
        app.run(debug=APP_DEBUG, host=APP_HOST, port=APP_PORT)
