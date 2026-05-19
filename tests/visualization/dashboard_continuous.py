#!/usr/bin/env python3
"""
持续采集 + 实时可视化仪表板（基于 gen_vpn_logs.py 持续生成日志）
用法：python dashboard_continuous.py
"""

import os
import sys
import time
import uuid
import shutil
import socket
import subprocess
import threading
import signal
import random
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# --------------------------------------------
# 自动定位项目根目录
# --------------------------------------------
def find_project_root(start_path: Path) -> Path:
    for parent in [start_path] + list(start_path.parents):
        if (parent / "src" / "parsers" / "__init__.py").exists():
            return parent
    raise RuntimeError("未找到项目根目录（包含 src/parsers/__init__.py）")

SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = find_project_root(SCRIPT_DIR)
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from src.parsers import LogProcessor
    from src.utils.logger import get_logger
    print("[✓] parsers 模块导入成功")
except ImportError as e:
    print(f"[ERROR] 导入失败: {e}")
    sys.exit(1)

# --------------------------------------------
# 配置（基于项目根目录）
# --------------------------------------------
KAFKA_BOOTSTRAP = "localhost:9092"
KAFKA_TOPIC = "logs_raw"
CLICKHOUSE_HOST = "localhost"
CLICKHOUSE_PORT = 8123
CLICKHOUSE_DATABASE = "test_logs"
CLICKHOUSE_TABLE = "structured_logs"
CLICKHOUSE_USER = "default"
CLICKHOUSE_PASSWORD = ""

TEST_TMP = PROJECT_ROOT / "test_tmp"
MONITORED_LOGS_DIR = TEST_TMP / "monitored_logs"      # Filebeat 监控的目录
FILEBEAT_DATA_DIR = TEST_TMP / "filebeat_data"
FILEBEAT_LOGS_DIR = TEST_TMP / "filebeat_logs"
FILEBEAT_CONFIG_DIR = TEST_TMP / "filebeat_config"
COMPOSE_FILE = TEST_TMP / "docker-compose.yml"
GEN_VPN_SCRIPT = PROJECT_ROOT / "tests" / "collectors" / "gen_vpn_logs.py"

DASHBOARD_PATH = PROJECT_ROOT / "src" / "visualization" / "dashboard.py"

# 持续生成参数
LOG_GEN_INTERVAL_SEC = 5        # 每5秒生成一批新日志
LOGS_PER_BATCH = 5              # 每批生成5条日志（可调）
DAYS_PER_BATCH = 1              # 每次生成跨越1天的日志（时间戳会变化）

# --------------------------------------------
# 输出辅助
# --------------------------------------------
class Fmt:
    @staticmethod
    def header(txt): print(f"\n{'='*60}\n {txt}\n{'='*60}")
    @staticmethod
    def step(n, txt): print(f"\n[{n}] {txt}...")
    @staticmethod
    def ok(txt): print(f"[✓] {txt}")
    @staticmethod
    def err(txt): print(f"[✗] {txt}")
    @staticmethod
    def info(txt): print(f" [i] {txt}")
    @staticmethod
    def warn(txt): print(f"[!] {txt}")

# --------------------------------------------
# 依赖检查（与原来相同）
# --------------------------------------------
def check_prerequisites():
    Fmt.step(1, "检查系统依赖")
    try:
        subprocess.run(["sudo", "docker", "--version"], check=True, capture_output=True)
        Fmt.ok("Docker 已安装且可使用 sudo")
    except:
        Fmt.err("Docker 未安装或 sudo 权限不足")
        return False
    try:
        subprocess.run(["sudo", "filebeat", "version"], check=True, capture_output=True)
        Fmt.ok("Filebeat 已安装且可使用 sudo")
    except:
        Fmt.err("Filebeat 未安装或 sudo 权限不足")
        return False

    packages = [("kafka-python", "kafka"), ("clickhouse-connect", "clickhouse_connect"),
                ("pyyaml", "yaml"), ("loguru", "loguru"), ("streamlit", "streamlit")]
    missing = []
    for pkg_name, import_name in packages:
        try:
            __import__(import_name)
            Fmt.ok(f"{pkg_name} 已安装")
        except ImportError:
            missing.append(pkg_name)
            Fmt.err(f"{pkg_name} 未安装")
    if missing:
        Fmt.err(f"缺少包: {', '.join(missing)}")
        Fmt.info("请运行: pip install " + " ".join(missing))
        return False
    return True

# --------------------------------------------
# 启动 Kafka + ClickHouse（与原来相同）
# --------------------------------------------
def start_services():
    Fmt.step(2, "启动 Kafka + ClickHouse 容器")
    compose_content = f"""
services:
  kafka:
    image: apache/kafka:latest
    container_name: test_integration_kafka
    environment:
      KAFKA_NODE_ID: 1
      KAFKA_PROCESS_ROLES: broker,controller
      KAFKA_CONTROLLER_QUORUM_VOTERS: 1@localhost:9093
      KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT
      KAFKA_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
    ports:
      - "9092:9092"
  clickhouse:
    image: clickhouse/clickhouse-server:latest
    container_name: test_integration_clickhouse
    ports:
      - "8123:8123"
      - "9000:9000"
    environment:
      CLICKHOUSE_DB: {CLICKHOUSE_DATABASE}
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: 1
    ulimits:
      nofile:
        soft: 262144
        hard: 262144
"""
    TEST_TMP.mkdir(parents=True, exist_ok=True)
    with open(COMPOSE_FILE, 'w') as f:
        f.write(compose_content)

    # 清理端口占用
    for port in [8123, 9092]:
        result = subprocess.run(f"sudo lsof -t -i:{port}", shell=True, capture_output=True, text=True)
        if result.stdout.strip():
            for pid in result.stdout.strip().split('\n'):
                subprocess.run(f"sudo kill -9 {pid}", shell=True, stdout=subprocess.DEVNULL)
        time.sleep(1)

    subprocess.run(["sudo", "docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v"], stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "docker", "rm", "-f", "test_integration_kafka", "test_integration_clickhouse"], stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"], check=True)

    # 等待 Kafka
    for i in range(30):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex(('localhost', 9092)) == 0:
            sock.close()
            break
        sock.close()
        time.sleep(2)
    else:
        raise RuntimeError("Kafka 启动超时")
    Fmt.ok("Kafka 已就绪")

    # 等待 ClickHouse
    import clickhouse_connect
    for i in range(60):
        try:
            client = clickhouse_connect.get_client(
                host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
                username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
                database=CLICKHOUSE_DATABASE, connect_timeout=3
            )
            client.command("SELECT 1")
            client.close()
            break
        except Exception as e:
            if i < 59:
                time.sleep(2)
            else:
                subprocess.run(["sudo", "docker", "logs", "test_integration_clickhouse"])
                raise RuntimeError("ClickHouse 启动超时")
    Fmt.ok("ClickHouse 已就绪")

    Fmt.info("创建 Kafka topic...")
    topic_cmd1 = [
        "sudo", "docker", "exec", "test_integration_kafka",
        "kafka-topics", "--create", "--topic", KAFKA_TOPIC,
        "--bootstrap-server", "localhost:9092",
        "--partitions", "1", "--replication-factor", "1"
    ]
    result = subprocess.run(topic_cmd1, capture_output=True, text=True)
    if result.returncode == 0:
        Fmt.ok(f"Kafka topic '{KAFKA_TOPIC}' 创建成功")
    elif "already exists" in result.stderr or "already exists" in result.stdout:
        Fmt.ok(f"Kafka topic '{KAFKA_TOPIC}' 已存在，继续使用")
    else:
        # 备用命令（使用绝对路径）
        topic_cmd2 = [
            "sudo", "docker", "exec", "test_integration_kafka",
            "/opt/kafka/bin/kafka-topics.sh", "--create", "--topic", KAFKA_TOPIC,
            "--bootstrap-server", "localhost:9092",
            "--partitions", "1", "--replication-factor", "1"
        ]
        result2 = subprocess.run(topic_cmd2, capture_output=True, text=True)
        if result2.returncode == 0:
            Fmt.ok(f"Kafka topic '{KAFKA_TOPIC}' 创建成功")
        elif "already exists" in result2.stderr or "already exists" in result2.stdout:
            Fmt.ok(f"Kafka topic '{KAFKA_TOPIC}' 已存在，继续使用")
        else:
            raise RuntimeError(f"创建 topic 失败: {result2.stderr or result2.stdout}")

    # 创建 ClickHouse 表
    create_table_sql = f"""
    CREATE TABLE IF NOT EXISTS {CLICKHOUSE_TABLE} (
        timestamp DateTime64(3),
        log_type String,
        username String,
        action String,
        source_ip String,
        destination_ip String,
        user_agent String,
        uri String,
        method String,
        status_code Int32,
        response_time Float64,
        detail String,
        severity_level String,
        event_type String,
        session_id String,
        request_id String,
        raw_message String,
        parser String,
        parse_status String,
        collected_at DateTime64(3)
    ) ENGINE = MergeTree() ORDER BY (log_type, timestamp)
    """
    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE
    )
    ch_client.command(create_table_sql)
    ch_client.close()
    Fmt.ok(f"ClickHouse 表 '{CLICKHOUSE_TABLE}' 已就绪")

# --------------------------------------------
# 持续日志生成器（线程）
# --------------------------------------------
def continuous_log_generator(stop_event: threading.Event):
    """持续生成简单格式的日志（与原 dashboard_test.py 相同）"""
    Fmt.info("启动简单日志生成器线程...")
    MONITORED_LOGS_DIR.mkdir(parents=True, exist_ok=True)

    users = ["alice", "bob", "charlie", "david", "eve"]
    actions = ["LOGIN", "LOGOUT"]
    batch_counter = 0

    while not stop_event.is_set():
        batch_counter += 1
        # 每次生成一个带时间戳的新文件
        filename = f"simple_batch_{batch_counter}_{int(time.time())}.log"
        filepath = MONITORED_LOGS_DIR / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            for _ in range(LOGS_PER_BATCH):
                # 随机生成一条日志
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                user = random.choice(users)
                action = random.choice(actions)
                ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
                line = f"{ts} {action} user={user} ip={ip} status=SUCCESS\n"
                f.write(line)

        Fmt.info(f"生成了 {LOGS_PER_BATCH} 条简单日志 -> {filename}")

        # 等待下一个周期
        for _ in range(LOG_GEN_INTERVAL_SEC):
            if stop_event.is_set():
                break
            time.sleep(1)

# --------------------------------------------
# Filebeat 启动（持续监控）
# --------------------------------------------
def start_filebeat() -> subprocess.Popen:
    Fmt.step(3, "启动 Filebeat 持续采集")
    subprocess.run(["sudo", "pkill", "-f", "filebeat"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    for d in [FILEBEAT_DATA_DIR, FILEBEAT_LOGS_DIR, FILEBEAT_CONFIG_DIR]:
        if d.exists():
            subprocess.run(["sudo", "rm", "-rf", str(d)], check=False)
        d.mkdir(parents=True)

    config_path = FILEBEAT_CONFIG_DIR / "filebeat.yml"
    config_content = f"""
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - {MONITORED_LOGS_DIR}/*.log
  fields:
    log_type: vpn
  fields_under_root: true

output.kafka:
  hosts: ["{KAFKA_BOOTSTRAP}"]
  topic: "{KAFKA_TOPIC}"
  partition.round_robin:
    reachable_only: false
  required_acks: 1
  compression: gzip

logging.level: warning
logging.to_files: true
logging.files:
  path: {FILEBEAT_LOGS_DIR}
  name: filebeat
  keepfiles: 7
"""
    with open(config_path, 'w') as f:
        f.write(config_content)

    cmd = [
        "sudo", "filebeat", "-e",
        "-c", str(config_path.absolute()),
        "--path.data", str(FILEBEAT_DATA_DIR),
        "--path.logs", str(FILEBEAT_LOGS_DIR),
        "--strict.perms=false",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    Fmt.ok(f"Filebeat 已启动，PID: {proc.pid}")
    time.sleep(10)
    return proc

# --------------------------------------------
# 持续 Kafka 消费 -> ClickHouse 写入（线程）
# --------------------------------------------
def continuous_ingester(stop_event: threading.Event):
    """持续消费 Kafka，使用 LogProcessor 解析并写入 ClickHouse"""
    from kafka import KafkaConsumer
    import clickhouse_connect

    group_id = f"continuous_group_{uuid.uuid4().hex[:8]}"
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=group_id,
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        value_deserializer=lambda m: m.decode('utf-8')
    )
    Fmt.info(f"Kafka 消费者 group_id={group_id} 已启动")

    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE
    )

    # 初始化 LogProcessor
    log_processor = LogProcessor(config={})

    buffer = []
    buffer_max_size = 50
    buffer_timeout = 5.0
    last_flush = time.time()

    def flush_buffer():
        nonlocal buffer, last_flush
        if not buffer:
            return

        columns = [
            'timestamp', 'log_type', 'username', 'action', 'source_ip',
            'destination_ip', 'user_agent', 'uri', 'method', 'status_code',
            'response_time', 'detail', 'severity_level', 'event_type',
            'session_id', 'request_id', 'raw_message', 'parser', 'parse_status',
            'collected_at'
        ]
        rows = []
        for log in buffer:
            ts = log.get('timestamp')
            if ts is None:
                continue
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                except:
                    ts = datetime.now(timezone.utc)
            row = []
            for col in columns:
                val = log.get(col)
                if val is None:
                    if col in ('timestamp', 'collected_at'):
                        val = datetime.now(timezone.utc)
                    elif col == 'status_code':
                        val = 0
                    elif col == 'response_time':
                        val = 0.0
                    else:
                        val = ''
                if col == 'status_code':
                    val = int(val) if str(val).isdigit() else 0
                elif col == 'response_time':
                    try:
                        val = float(val)
                    except:
                        val = 0.0
                elif col in ('timestamp', 'collected_at') and not isinstance(val, datetime):
                    try:
                        val = datetime.fromisoformat(str(val).replace('Z', '+00:00'))
                    except:
                        val = datetime.now(timezone.utc)
                else:
                    val = str(val) if val is not None else ''
                row.append(val)
            rows.append(row)

        if rows:
            try:
                ch_client.insert(CLICKHOUSE_TABLE, rows, column_names=columns)
                Fmt.info(f"已写入 {len(rows)} 条日志到 ClickHouse")
            except Exception as e:
                Fmt.err(f"写入失败: {e}")
        buffer = []
        last_flush = time.time()

    try:
        for msg in consumer:
            if stop_event.is_set():
                break
            raw = msg.value
            # 提取原始日志消息
            try:
                data = json.loads(raw)
                raw_log = data.get('message', raw)
            except:
                raw_log = raw

            # 使用 LogProcessor 解析
            parsed = log_processor.parse_log(raw_log)
            if not parsed:
                # 后备提取（如果解析失败，尝试简单正则，但简单格式一般能成功）
                import re
                match = re.search(r'user=(\w+)', raw_log)
                username = match.group(1) if match else 'unknown'
                match_ip = re.search(r'ip=([\d\.]+)', raw_log)
                source_ip = match_ip.group(1) if match_ip else '0.0.0.0'
                action = 'LOGIN' if 'LOGIN' in raw_log else ('LOGOUT' if 'LOGOUT' in raw_log else 'UNKNOWN')
                ts_match = re.search(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', raw_log)
                timestamp = ts_match.group(1) if ts_match else None
                if not timestamp:
                    continue
                parsed = {
                    'timestamp': timestamp,
                    'username': username,
                    'source_ip': source_ip,
                    'action': action,
                    'log_type': 'simple',
                }

            cleaned = log_processor.clean_log(parsed)
            if not cleaned:
                continue

            cleaned['raw_message'] = raw_log
            cleaned['collected_at'] = datetime.now(timezone.utc)
            cleaned['parse_status'] = 'success'
            buffer.append(cleaned)

            if len(buffer) >= buffer_max_size:
                flush_buffer()
            elif time.time() - last_flush > buffer_timeout:
                flush_buffer()
    finally:
        flush_buffer()
        consumer.close()
        ch_client.close()
        Fmt.info("持续消费线程已退出")

# --------------------------------------------
# 启动 Streamlit 仪表板
# --------------------------------------------
def start_streamlit() -> Optional[subprocess.Popen]:
    Fmt.step(5, "启动 Streamlit 可视化仪表板")
    if not DASHBOARD_PATH.exists():
        Fmt.err(f"仪表板文件未找到: {DASHBOARD_PATH}")
        return None
    cmd = [
        sys.executable, "-m", "streamlit", "run",
        str(DASHBOARD_PATH),
        "--server.port", "8501",
        "--server.address", "localhost",
        "--browser.serverAddress", "localhost"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    Fmt.ok(f"Streamlit 已启动，PID: {proc.pid}")
    time.sleep(5)
    print("\n" + "="*60)
    print(" ✅ 持续采集系统已就绪！")
    print(" 🌐 访问仪表板: http://localhost:8501")
    print(" 📡 日志持续生成并写入 ClickHouse")
    print(" 🔴 按 Ctrl+C 停止所有组件")
    print("="*60 + "\n")
    return proc

# --------------------------------------------
# 清理
# --------------------------------------------
def cleanup(filebeat_proc, streamlit_proc, stop_event):
    Fmt.step(6, "清理测试环境")
    stop_event.set()
    if filebeat_proc:
        filebeat_proc.terminate()
        try:
            filebeat_proc.wait(timeout=5)
        except:
            filebeat_proc.kill()
        subprocess.run(["sudo", "pkill", "-9", "-f", "filebeat"], stdout=subprocess.DEVNULL)
        Fmt.ok("Filebeat 已停止")
    if streamlit_proc:
        streamlit_proc.terminate()
        try:
            streamlit_proc.wait(timeout=5)
        except:
            streamlit_proc.kill()
        Fmt.ok("Streamlit 已停止")
    if COMPOSE_FILE.exists():
        subprocess.run(["sudo", "docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        COMPOSE_FILE.unlink(missing_ok=True)
        Fmt.ok("Docker 容器已清理")
    if TEST_TMP.exists():
        subprocess.run(["sudo", "rm", "-rf", str(TEST_TMP)], check=False)
        Fmt.ok("临时文件已清理")

# --------------------------------------------
# 主函数
# --------------------------------------------
def main():
    Fmt.header("日志分析 AI 助手 - 持续采集 + 实时仪表板")
    if not check_prerequisites():
        sys.exit(1)

    stop_event = threading.Event()
    filebeat_proc = None
    streamlit_proc = None

    def signal_handler(sig, frame):
        print("\n[!] 收到中断信号，正在清理...")
        cleanup(filebeat_proc, streamlit_proc, stop_event)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        start_services()
        # 确保监控目录存在
        MONITORED_LOGS_DIR.mkdir(parents=True, exist_ok=True)

        # 启动持续日志生成线程
        gen_thread = threading.Thread(target=continuous_log_generator, args=(stop_event,), daemon=True)
        gen_thread.start()

        # 启动 Filebeat
        filebeat_proc = start_filebeat()

        # 启动持续消费线程
        ingest_thread = threading.Thread(target=continuous_ingester, args=(stop_event,), daemon=True)
        ingest_thread.start()

        # 启动 Streamlit
        streamlit_proc = start_streamlit()
        if not streamlit_proc:
            cleanup(filebeat_proc, streamlit_proc, stop_event)
            sys.exit(1)

        # 保持主线程运行，等待中断
        while True:
            time.sleep(1)
            if filebeat_proc.poll() is not None:
                Fmt.err("Filebeat 进程意外退出")
                break
            if streamlit_proc.poll() is not None:
                Fmt.err("Streamlit 进程意外退出")
                break

    except Exception as e:
        Fmt.err(f"系统异常: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cleanup(filebeat_proc, streamlit_proc, stop_event)

if __name__ == "__main__":
    from datetime import timedelta
    main()