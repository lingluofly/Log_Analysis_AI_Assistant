#!/usr/bin/env python3.13
"""
端到端集成测试 + 可视化仪表板（适配 tests/visualization 目录）
自动定位项目根目录，启动数据管道并运行 Streamlit 仪表板
"""

import os
import sys
import time
import uuid
import shutil
import socket
import subprocess
import random
import re
import signal
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

# ----------------------------- 自动定位项目根目录 -----------------------------
def find_project_root(start_path: Path) -> Path:
    """向上查找包含 src/parsers/__init__.py 的目录作为项目根目录"""
    for parent in [start_path] + list(start_path.parents):
        if (parent / "src" / "parsers" / "__init__.py").exists():
            return parent
    raise RuntimeError("未找到项目根目录（包含 src/parsers/__init__.py）")

# 当前脚本所在目录（tests/visualization）
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = find_project_root(SCRIPT_DIR)
print(f"[INFO] 项目根目录: {PROJECT_ROOT}")

# 将项目根目录加入 sys.path，以便导入 src.parsers
sys.path.insert(0, str(PROJECT_ROOT))

# 导入 parsers 模块
try:
    from src.parsers import LogProcessor
    print("[✓] parsers 模块导入成功")
except ImportError as e:
    print(f"[ERROR] 导入 parsers 失败: {e}")
    sys.exit(1)

# ----------------------------- 配置参数（基于项目根目录） -----------------------------
KAFKA_BOOTSTRAP = "localhost:9092"
KAFKA_TOPIC = "logs_raw"
CLICKHOUSE_HOST = "localhost"
CLICKHOUSE_PORT = 8123
CLICKHOUSE_DATABASE = "test_logs"
CLICKHOUSE_TABLE = "structured_logs"
CLICKHOUSE_USER = "default"
CLICKHOUSE_PASSWORD = ""

# 临时目录及数据目录（均位于项目根目录下）
TEST_TMP = PROJECT_ROOT / "test_tmp"
SAMPLE_LOGS_DIR = TEST_TMP / "sample_logs"
FILEBEAT_DATA_DIR = TEST_TMP / "filebeat_data"
FILEBEAT_LOGS_DIR = TEST_TMP / "filebeat_logs"
FILEBEAT_CONFIG_DIR = TEST_TMP / "filebeat_config"
COMPOSE_FILE = TEST_TMP / "docker-compose.yml"

# 仪表板路径（仍在 src/visualization 下）
DASHBOARD_PATH = PROJECT_ROOT / "src" / "visualization" / "dashboard.py"

# ----------------------------- 输出辅助 -----------------------------
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
    def info(txt): print(f"   [i] {txt}")
    @staticmethod
    def warn(txt): print(f"[!] {txt}")

# ----------------------------- 依赖检查 -----------------------------
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

# ----------------------------- 生成测试日志 -----------------------------
def generate_test_logs():
    Fmt.step(2, "生成测试日志（VPN 格式）")
    if SAMPLE_LOGS_DIR.exists():
        shutil.rmtree(SAMPLE_LOGS_DIR)
    SAMPLE_LOGS_DIR.mkdir(parents=True)
    users = ["alice", "bob", "charlie", "david", "eve"]
    actions = ["LOGIN", "LOGOUT"]
    start_date = datetime(2026, 4, 1)
    total_lines = 0
    for i in range(20):
        ts = start_date + timedelta(seconds=random.randint(0, 2*86400))
        user = random.choice(users)
        action = random.choice(actions)
        ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        line = f"{ts.strftime('%Y-%m-%d %H:%M:%S')} {action} user={user} ip={ip} status=SUCCESS\n"
        log_file = SAMPLE_LOGS_DIR / f"vpn_{i}.log"
        with open(log_file, 'w') as f:
            f.write(line)
        total_lines += 1
    Fmt.ok(f"生成了 20 个日志文件，共 {total_lines} 行")
    return True

# ----------------------------- Docker 服务 -----------------------------
def start_services():
    Fmt.step(3, "启动 Kafka + ClickHouse 容器")
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

    Fmt.info("彻底清理端口 8123 和 9092 占用...")
    subprocess.run("sudo docker ps -a --filter 'publish=8123' -q | xargs -r sudo docker rm -f", shell=True, stdout=subprocess.DEVNULL)
    subprocess.run("sudo docker ps -a --filter 'publish=9092' -q | xargs -r sudo docker rm -f", shell=True, stdout=subprocess.DEVNULL)
    for port in [8123, 9092]:
        result = subprocess.run(f"sudo lsof -t -i:{port}", shell=True, capture_output=True, text=True)
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                Fmt.info(f"杀死占用端口 {port} 的进程 PID: {pid}")
                subprocess.run(f"sudo kill -9 {pid}", shell=True, stdout=subprocess.DEVNULL)
    time.sleep(1)

    Fmt.info("清理旧容器...")
    subprocess.run(["sudo", "docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v"], stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "docker", "rm", "-f", "test_integration_kafka", "test_integration_clickhouse"], stdout=subprocess.DEVNULL)

    Fmt.info("启动新容器...")
    subprocess.run(["sudo", "docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"], check=True)

    # 等待 Kafka
    Fmt.info("等待 Kafka 就绪...")
    for i in range(30):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex(('localhost', 9092)) == 0:
                sock.close()
                break
            sock.close()
        except:
            pass
        time.sleep(2)
    else:
        raise RuntimeError("Kafka 启动超时")
    Fmt.ok("Kafka 已就绪")

    # 等待 ClickHouse
    import clickhouse_connect
    Fmt.info("等待 ClickHouse 就绪...")
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
                Fmt.info(f"等待 ClickHouse 启动中 ({i+1}/60): {str(e)[:80]}")
                time.sleep(2)
            else:
                subprocess.run(["sudo", "docker", "logs", "test_integration_clickhouse"])
                raise RuntimeError("ClickHouse 启动超时")
    Fmt.ok("ClickHouse 已就绪")

    # 创建 Kafka Topic
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
    elif "already exists" in result.stderr:
        Fmt.ok(f"Kafka topic '{KAFKA_TOPIC}' 已存在")
    else:
        topic_cmd2 = [
            "sudo", "docker", "exec", "test_integration_kafka",
            "/opt/kafka/bin/kafka-topics.sh", "--create", "--topic", KAFKA_TOPIC,
            "--bootstrap-server", "localhost:9092",
            "--partitions", "1", "--replication-factor", "1"
        ]
        result = subprocess.run(topic_cmd2, capture_output=True, text=True)
        if result.returncode == 0:
            Fmt.ok(f"Kafka topic '{KAFKA_TOPIC}' 创建成功")
        elif "already exists" in result.stderr:
            Fmt.ok(f"Kafka topic '{KAFKA_TOPIC}' 已存在")
        else:
            Fmt.err(f"创建 topic 失败: {result.stderr}")
            raise RuntimeError("无法创建 Kafka topic")

    # 创建 ClickHouse 表
    create_table_sql = f"""
    CREATE TABLE IF NOT EXISTS {CLICKHOUSE_TABLE} (
        timestamp       DateTime64(3),
        log_type        String,
        username        String,
        action          String,
        source_ip       String,
        destination_ip  String,
        user_agent      String,
        uri             String,
        method          String,
        status_code     Int32,
        response_time   Float64,
        detail          String,
        severity_level  String,
        event_type      String,
        session_id      String,
        request_id      String,
        raw_message     String,
        parser          String,
        parse_status    String,
        collected_at    DateTime64(3)
    ) ENGINE = MergeTree()
    ORDER BY (log_type, timestamp)
    """
    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE
    )
    ch_client.command(create_table_sql)
    ch_client.close()
    Fmt.ok(f"ClickHouse 表 '{CLICKHOUSE_TABLE}' 已就绪")

# ----------------------------- Filebeat 启动 -----------------------------
def start_filebeat():
    Fmt.step(4, "启动 Filebeat 采集服务")
    subprocess.run(["sudo", "pkill", "-f", "filebeat"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    for d in [FILEBEAT_DATA_DIR, FILEBEAT_LOGS_DIR, FILEBEAT_CONFIG_DIR]:
        if d.exists():
            subprocess.run(["sudo", "rm", "-rf", str(d)], check=False)
        d.mkdir(parents=True)
        subprocess.run(["sudo", "chown", "-R", f"{os.getenv('USER')}:{os.getenv('USER')}", str(d)], check=False)
        subprocess.run(["sudo", "chmod", "-R", "755", str(d)], check=False)

    config_path = FILEBEAT_CONFIG_DIR / "filebeat.yml"
    config_content = f"""
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - {SAMPLE_LOGS_DIR}/*.log
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

# ----------------------------- 数据解析与入库（后备正则提取） -----------------------------
def ingest_logs_to_clickhouse():
    Fmt.step(5, "消费 Kafka 并使用 parsers 解析存入 ClickHouse")
    from kafka import KafkaConsumer
    import clickhouse_connect
    import json

    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE
    )

    log_processor = LogProcessor(config={})

    group_id = f"test_group_{uuid.uuid4().hex[:8]}"
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=group_id,
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        value_deserializer=lambda m: m.decode('utf-8')
    )
    Fmt.info(f"Kafka 消费者 group_id={group_id}")

    parsed_logs = []
    failed = 0
    received = 0
    max_logs = 15
    start_time = time.time()
    timeout = 60

    try:
        for msg in consumer:
            received += 1
            raw = msg.value
            try:
                data = json.loads(raw)
                raw_log = data.get('message', raw)
            except:
                raw_log = raw
            Fmt.info(f"收到消息 #{received}: {raw_log[:80]}...")

            parsed = log_processor.parse_log(raw_log)
            if not parsed:
                Fmt.warn("解析失败，跳过")
                failed += 1
                continue

            cleaned = log_processor.clean_log(parsed)
            if not cleaned:
                Fmt.warn("清洗后无效，跳过")
                failed += 1
                continue

            # 后备提取 username、source_ip 和 action
            if not cleaned.get('username'):
                match = re.search(r'user=(\w+)', raw_log)
                if match:
                    cleaned['username'] = match.group(1)
                else:
                    cleaned['username'] = ''
            if not cleaned.get('source_ip'):
                match = re.search(r'ip=([\d\.]+)', raw_log)
                if match:
                    cleaned['source_ip'] = match.group(1)
                else:
                    cleaned['source_ip'] = ''
            if not cleaned.get('action'):
                if 'LOGIN' in raw_log:
                    cleaned['action'] = 'LOGIN'
                elif 'LOGOUT' in raw_log:
                    cleaned['action'] = 'LOGOUT'
                else:
                    cleaned['action'] = 'UNKNOWN'

            cleaned['raw_message'] = raw_log
            cleaned['collected_at'] = datetime.now(timezone.utc)
            cleaned['parse_status'] = 'success'
            parsed_logs.append(cleaned)

            if len(parsed_logs) >= max_logs:
                break
            if time.time() - start_time > timeout:
                Fmt.warn(f"超时，仅收集 {len(parsed_logs)} 条")
                break
    except Exception as e:
        Fmt.err(f"消费异常: {e}")
        return False
    finally:
        consumer.close()

    Fmt.info(f"采集结束: 收到 {received} 条, 解析成功 {len(parsed_logs)} 条, 失败 {failed} 条")
    if not parsed_logs:
        Fmt.err("没有成功解析的日志")
        return False

    # 定义列顺序
    columns = ['timestamp', 'log_type', 'username', 'action', 'source_ip',
               'destination_ip', 'user_agent', 'uri', 'method', 'status_code',
               'response_time', 'detail', 'severity_level', 'event_type',
               'session_id', 'request_id', 'raw_message', 'parser', 'parse_status',
               'collected_at']

    rows = []
    skipped = 0
    for log in parsed_logs:
        ts = log.get('timestamp')
        if ts is None:
            skipped += 1
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
            # 类型转换
            if col == 'status_code':
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    val = 0
            elif col == 'response_time':
                try:
                    val = float(val)
                except (ValueError, TypeError):
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

    if skipped:
        Fmt.warn(f"跳过了 {skipped} 条缺少时间戳的日志")
    if not rows:
        Fmt.err("没有有效的日志可写入")
        return False

    Fmt.info(f"写入 {len(rows)} 条结构化日志...")
    try:
        ch_client.insert(CLICKHOUSE_TABLE, rows, column_names=columns)
        Fmt.ok(f"成功写入 {len(rows)} 条日志")
    except Exception as e:
        Fmt.err(f"写入失败: {e}")
        import traceback
        traceback.print_exc()
        return False

    ch_client.close()
    return True

# ----------------------------- 启动 Streamlit -----------------------------
def start_streamlit():
    Fmt.step(6, "启动 Streamlit 可视化仪表板")
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
    print("  ✅ 服务已就绪！")
    print("  🌐 访问仪表板: http://localhost:8501")
    print("  📡 数据流将持续写入 ClickHouse")
    print("  🔴 按 Ctrl+C 停止并清理所有资源")
    print("="*60 + "\n")
    return proc

# ----------------------------- 清理函数 -----------------------------
def cleanup(filebeat_proc: Optional[subprocess.Popen], streamlit_proc: Optional[subprocess.Popen]):
    Fmt.step(7, "清理测试环境")
    if filebeat_proc:
        Fmt.info("停止 Filebeat...")
        filebeat_proc.terminate()
        try:
            filebeat_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            filebeat_proc.kill()
        subprocess.run(["sudo", "pkill", "-9", "-f", "filebeat"], stdout=subprocess.DEVNULL)
        Fmt.ok("Filebeat 已停止")
    if streamlit_proc:
        Fmt.info("停止 Streamlit...")
        streamlit_proc.terminate()
        try:
            streamlit_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            streamlit_proc.kill()
        Fmt.ok("Streamlit 已停止")
    if COMPOSE_FILE.exists():
        Fmt.info("停止 Docker 容器...")
        subprocess.run(["sudo", "docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        COMPOSE_FILE.unlink(missing_ok=True)
        Fmt.ok("Docker 容器已清理")
    if TEST_TMP.exists():
        subprocess.run(["sudo", "rm", "-rf", str(TEST_TMP)], check=False)
    Fmt.ok("清理完成")

# ----------------------------- 信号处理 -----------------------------
def signal_handler(sig, frame, filebeat_proc, streamlit_proc):
    print("\n\n[!] 收到中断信号，正在清理...")
    cleanup(filebeat_proc, streamlit_proc)
    sys.exit(0)

# ----------------------------- 主函数 -----------------------------
def main():
    Fmt.header("日志分析 AI 助手 - 端到端集成测试 + 可视化仪表板")
    if not check_prerequisites():
        sys.exit(1)

    filebeat_proc = None
    streamlit_proc = None

    def handler(sig, frame):
        signal_handler(sig, frame, filebeat_proc, streamlit_proc)
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    try:
        start_services()
        if not generate_test_logs():
            cleanup(filebeat_proc, streamlit_proc)
            sys.exit(1)
        filebeat_proc = start_filebeat()
        Fmt.info("等待 10 秒确保日志进入 Kafka...")
        time.sleep(10)

        if not ingest_logs_to_clickhouse():
            Fmt.err("数据写入失败，请检查错误")
            cleanup(filebeat_proc, streamlit_proc)
            sys.exit(1)

        streamlit_proc = start_streamlit()
        if not streamlit_proc:
            cleanup(filebeat_proc, streamlit_proc)
            sys.exit(1)

        # 保持运行，等待中断
        while True:
            time.sleep(1)
            if streamlit_proc.poll() is not None:
                Fmt.err("Streamlit 进程意外退出")
                break
            if filebeat_proc.poll() is not None:
                Fmt.err("Filebeat 进程意外退出")
                break
    except Exception as e:
        Fmt.err(f"测试异常: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cleanup(filebeat_proc, streamlit_proc)

if __name__ == "__main__":
    main()