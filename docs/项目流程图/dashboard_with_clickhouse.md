# dashboard_test.py 使用手册（基于日志分析项目）

本手册基于重点介绍如何通过集成测试脚本 `dashboard_test.py` 一键启动日志采集、解析、存储及可视化仪表板，并附 ClickHouse 运维要点。

## 1. 快速体验：一键运行完整数据流

项目提供了端到端测试脚本 `dashboard_test.py`，它会自动完成以下工作：
- 使用 Docker Compose 启动 **Kafka + ClickHouse** 容器
- 生成 VPN 格式的测试日志文件
- 启动 **Filebeat** 采集日志并发送到 Kafka
- 消费 Kafka 消息，调用 **parsers 模块** 解析为标准结构化日志
- 将解析后的日志写入 ClickHouse 的 `structured_logs` 表
- 启动 **Streamlit 可视化仪表板**，展示实时日志和安全看板

### 1.1 环境要求

- **操作系统**：ubuntu22.04
- **软件依赖**：
  - Docker lastest
  - Filebeat 8.19.13
  - Python 3.13
- **Python 包**：见 `requirements.txt`（使用虚拟环境）

### 1.2 安装步骤

```bash
# 1. 克隆项目（假设项目根目录为 ~/Log_Analysis_AI_Assistant）
cd ~/Log_Analysis_AI_Assistant

# 2. 创建虚拟环境并激活
python3 -m venv venv
source venv/bin/activate

# 3. 安装 Python 依赖
pip install -r requirements.txt
# 或手动安装核心包：
pip install kafka-python clickhouse-connect pyyaml loguru streamlit fpdf pandas

# 4. 确保 Docker 与 Filebeat 已安装，且当前用户有 sudo 权限
sudo systemctl enable docker
sudo systemctl start docker
sudo filebeat version   # 验证 Filebeat 可用

# 5. 运行测试脚本（脚本位于 tests/visualization/）
python3.13 tests/visualization/dashboard_test.py
```

### 1.3 脚本运行说明

- 启动后，脚本会输出关键步骤日志，最终显示：
  ```
  ✅ 服务已就绪！
  🌐 访问仪表板: http://localhost:8501
  ```
- 使用浏览器打开该地址，即可看到**实时日志流**等页面，数据来源于 ClickHouse 真实表。
- 按 `Ctrl+C` 停止脚本，会自动清理 Docker 容器、临时文件及 Filebeat 进程。

### 1.4 验证数据写入

在脚本运行期间，可另开终端确认 ClickHouse 中已存入数据：

```bash
# 进入 ClickHouse 容器
docker exec -it test_integration_clickhouse clickhouse-client --query "SELECT count(*) FROM test_logs.structured_logs"
# 预期输出非零数字，如 15
```

---

## 2. ClickHouse 核心配置（供仪表板调用）

仪表板中的 `fetch_realtime_logs` 函数会直接连接 ClickHouse，其关键参数如下：

| 参数       | 取值                      | 说明                     |
| ---------- | ------------------------- | ------------------------ |
| host       | `localhost`               | 容器宿主机地址           |
| port       | `8123`                    | HTTP 端口                |
| username   | `default`                 | 默认用户                 |
| password   | `''` (空字符串)           | **测试环境使用空密码**   |
| database   | `test_logs`               | 与测试脚本写入一致       |
| table      | `structured_logs`         | 存储结构化日志的表       |

**重要**：测试环境中使用了**空密码**，这是为了简化 Docker 容器启动（避免设置密码后客户端连接困难）。生产环境务必设置强密码。

---

## 3. 故障排查要点

### 3.1 端口冲突：`address already in use`

- 检查并终止占用 8123（ClickHouse）或 9092（Kafka）的进程：
  ```bash
  sudo lsof -i :8123
  sudo kill -9 <PID>
  ```
- 清理残留容器：`sudo docker rm -f test_integration_clickhouse test_integration_kafka`

### 3.2 ClickHouse 连接失败

- 确认容器已启动：`sudo docker ps | grep clickhouse`
- 测试连通性：`docker exec -it test_integration_clickhouse clickhouse-client --query "SELECT 1"`
- 如果仪表板报错 `Database log_analysis does not exist`，是因为默认数据库不匹配，请按修改后的 `fetch_realtime_logs` 使用 `database='test_logs'`。

### 3.3 仪表板显示模拟数据而非真实日志

- 检查 `structured_logs` 表是否有数据（用上述 `count(*)` 验证）。
- 确认 `dashboard.py` 中的 `fetch_realtime_logs` 已按手册修改为连接 `test_logs` 库并查询 `structured_logs` 表。
- 重启脚本，确保数据已重新生成并写入。

### 3.4 Filebeat 权限错误

- 脚本内部使用 `sudo filebeat` 运行，需确保当前用户无密码 sudo 或输入密码后运行脚本。
- 临时文件目录 `test_tmp` 可能权限不足，脚本已自动执行 `sudo chown`，一般无需手动干预。

---

## 4. ClickHouse 常用操作（供调试）

### 4.1 查询表结构

```sql
DESCRIBE test_logs.structured_logs;
```

### 4.2 查看最近 5 条日志（含用户名和 IP）

```sql
SELECT timestamp, username, source_ip, action, raw_message
FROM test_logs.structured_logs
ORDER BY timestamp DESC
LIMIT 5
FORMAT Vertical;
```

### 4.3 统计每小时日志量

```sql
SELECT toStartOfHour(timestamp) AS hour, count(*)
FROM test_logs.structured_logs
GROUP BY hour
ORDER BY hour DESC;
```

---

## 5. 总结

- **测试脚本 `dashboard_test.py`** 是项目的“启动器”，它整合了数据生成、采集、解析、存储、可视化全流程，无需单独配置 Kafka/ClickHouse 即可体验日志分析能力。
- **ClickHouse** 在其中作为标准化的日志存储引擎，所有结构化字段（用户名、IP、动作等）均可直接用于仪表板查询和聚合。
- 遇到问题时，优先检查 Docker 容器状态、表数据是否存在，并确保仪表板连接参数与测试脚本写入的库/表一致。