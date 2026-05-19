#!/usr/bin/env python3.13
"""
采集模块 + parsers 解析模块 + 存储模块端到端集成测试
使用真实的 src.utils.logger
"""

import os
import sys
import time
import uuid
import shutil
import socket
import subprocess
import random
import logging
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

# ======================== 禁止 root 运行 ========================
if os.geteuid() == 0:
    print("[ERROR] 请勿使用 sudo 或 root 运行此脚本！")
    print("       请激活虚拟环境后，直接运行: python3.13 script.py")
    sys.exit(1)

# ======================== 自动定位项目根目录 ========================
def find_project_root(start_path: Path) -> Path:
    for parent in [start_path] + list(start_path.parents):
        if (parent / "src" / "parsers" / "__init__.py").exists():
            return parent
    raise RuntimeError("未找到项目根目录（包含 src/parsers/__init__.py）")

SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = find_project_root(SCRIPT_DIR)
print(f"[INFO] 项目根目录: {PROJECT_ROOT}")

# 将项目根目录加入 sys.path
sys.path.insert(0, str(PROJECT_ROOT))

# 直接导入 parsers 模块（现在会真实使用 src.utils.logger）
try:
    from src.parsers import LogProcessor
    print("[✓] parsers 模块导入成功")
except ImportError as e:
    print(f"[ERROR] 导入 parsers 失败: {e}")
    print("请确保已安装 loguru，并且 src/utils/config.py 存在")
    sys.exit(1)

# ======================== 测试配置 ========================
KAFKA_BOOTSTRAP = "localhost:9092"
KAFKA_TOPIC = "logs_raw"
CLICKHOUSE_HOST = "localhost"
CLICKHOUSE_PORT = 8123
CLICKHOUSE_DATABASE = "test_logs"
CLICKHOUSE_TABLE = "structured_logs"
CLICKHOUSE_USER = "default"
CLICKHOUSE_PASSWORD = ""

TEST_TMP = PROJECT_ROOT / "test_tmp"
SAMPLE_LOGS_DIR = TEST_TMP / "sample_logs"
FILEBEAT_DATA_DIR = TEST_TMP / "filebeat_data"
FILEBEAT_LOGS_DIR = TEST_TMP / "filebeat_logs"
FILEBEAT_CONFIG_DIR = TEST_TMP / "filebeat_config"
COMPOSE_FILE = TEST_TMP / "docker-compose.yml"

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

# ======================== 依赖检查 ========================
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
    packages = [("kafka-python", "kafka"), ("clickhouse-connect", "clickhouse_connect"), ("pyyaml", "yaml"), ("loguru", "loguru")]
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

# ======================== 生成测试日志 ========================
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

# ======================== Docker 服务启动 ========================
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
    subprocess.run("sudo docker ps -a --filter 'publish=8123' -q | xargs -r sudo docker rm -f",
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run("sudo docker ps -a --filter 'publish=9092' -q | xargs -r sudo docker rm -f",
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for port in [8123, 9092]:
        result = subprocess.run(f"sudo lsof -t -i:{port}", shell=True, capture_output=True, text=True)
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                Fmt.info(f"杀死占用端口 {port} 的进程 PID: {pid}")
                subprocess.run(f"sudo kill -9 {pid}", shell=True, stdout=subprocess.DEVNULL)
    time.sleep(1)

    Fmt.info("清理旧容器...")
    subprocess.run(["sudo", "docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "docker", "rm", "-f", "test_integration_kafka", "test_integration_clickhouse"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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
                username=CLICKHOUSE_USER,
                password=CLICKHOUSE_PASSWORD,
                database=CLICKHOUSE_DATABASE,
                connect_timeout=3
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

    # 创建 ClickHouse 结构化表
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
        username=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE
    )
    ch_client.command(create_table_sql)
    ch_client.close()
    Fmt.ok(f"ClickHouse 表 '{CLICKHOUSE_TABLE}' 已就绪")

# ======================== Filebeat 启动 ========================
def start_filebeat():
    Fmt.step(4, "启动 Filebeat 采集服务")
    subprocess.run(["sudo", "pkill", "-f", "filebeat"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    for d in [FILEBEAT_DATA_DIR, FILEBEAT_LOGS_DIR, FILEBEAT_CONFIG_DIR]:
        if d.exists():
            shutil.rmtree(d)
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

# ======================== 采集 + 解析 + 存储 ========================
def test_collect_parse_store(filebeat_proc):
    Fmt.step(5, "Kafka 消费并使用 parsers 解析后存入 ClickHouse")
    from kafka import KafkaConsumer
    import clickhouse_connect
    import json

    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
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
            Fmt.warn(f"跳过缺少时间戳的日志")
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
                elif col in ('status_code',):
                    val = 0
                elif col in ('response_time',):
                    val = 0.0
                else:
                    val = ''
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
            elif col in ('timestamp', 'collected_at'):
                if not isinstance(val, datetime):
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

    time.sleep(2)
    try:
        result = ch_client.query(f"SELECT count(*) FROM {CLICKHOUSE_TABLE}")
        cnt = result.first_row[0]
        Fmt.ok(f"ClickHouse 验证通过，表中共 {cnt} 条记录")
    except Exception as e:
        Fmt.err(f"验证查询失败: {e}")

    ch_client.close()
    return True

# ======================== 清理环境 ========================
def cleanup(filebeat_proc: Optional[subprocess.Popen]):
    Fmt.step(6, "清理测试环境")
    if filebeat_proc:
        Fmt.info("停止 Filebeat...")
        filebeat_proc.terminate()
        try:
            filebeat_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            filebeat_proc.kill()
        subprocess.run(["sudo", "pkill", "-9", "-f", "filebeat"], stdout=subprocess.DEVNULL)
        Fmt.ok("Filebeat 已停止")
    if COMPOSE_FILE.exists():
        Fmt.info("停止 Docker 容器...")
        subprocess.run(["sudo", "docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        COMPOSE_FILE.unlink(missing_ok=True)
        Fmt.ok("Docker 容器已清理")
    if TEST_TMP.exists():
        shutil.rmtree(TEST_TMP, ignore_errors=True)
    Fmt.ok("临时目录已删除")

# ======================== 主函数 ========================
def main():
    Fmt.header("采集 + parsers 解析 + 存储 端到端集成测试")
    if not check_prerequisites():
        sys.exit(1)

    filebeat_proc = None
    try:
        start_services()
        if not generate_test_logs():
            cleanup(filebeat_proc)
            sys.exit(1)
        filebeat_proc = start_filebeat()
        Fmt.info("等待 10 秒确保日志进入 Kafka...")
        time.sleep(10)
        success = test_collect_parse_store(filebeat_proc)
        Fmt.header("测试结果")
        if success:
            Fmt.ok("端到端测试通过！")
        else:
            Fmt.err("测试失败")
            sys.exit(1)
    except Exception as e:
        Fmt.err(f"测试异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        cleanup(filebeat_proc)

if __name__ == "__main__":
    main()