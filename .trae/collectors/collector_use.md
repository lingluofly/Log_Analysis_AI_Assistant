# Log Analysis AI Assistant - 采集模块使用文档

## 1. 概述

本采集模块提供两个 Kafka 消费者实现：

- **FilebeatCollector**：消费由 Filebeat 推送的日志（通常包含丰富的元数据，如 `host`、`log_type`、`source` 路径等）。
- **FlumeCollector**：消费由 Flume 或任何符合简单 JSON 格式的日志生成器推送的日志，支持批量拉取，适用于高吞吐场景。

两者均继承自 `BaseCollector`，共享日志验证与丰富逻辑。

**重要更新**：Filebeat 已实现容器化部署，无需在宿主机安装。

## 2. 环境要求与版本清单

| 组件             | 最低版本   | 测试版本     | 用途               |
| ---------------- | ---------- | ------------ | ------------------ |
| Python           | 3.9        | 3.10.x       | 运行采集器         |
| kafka-python     | 2.3.0      | 2.3.0        | Kafka 客户端       |
| Apache Kafka     | 3.0        | 3.7.0        | 消息队列（容器化） |
| Filebeat         | 8.x        | 8.13.0       | 日志采集（容器化） |
| ClickHouse       | 22.0       | 24.x         | 数据存储（容器化） |
| Docker           | 20.10      | 最新         | 容器运行           |
| Docker Compose   | 2.0        | v5.1.1       | 容器编排           |

## 3. 快速测试指南

### 3.1 使用集成测试脚本（推荐）

项目已提供完整的集成测试脚本，一键运行所有测试：

```bash
# 进入项目根目录
cd ~/programs/Log_Analysis_AI_Assistant

# 激活虚拟环境
source venv/bin/activate

# 启动 Docker 服务（如未启动）
sudo systemctl enable docker
sudo systemctl start docker

# 确保日志目录存在
mkdir -p logs/filebeat

# 运行集成测试（通过 setup_project.sh）
./tests/collectors/setup_project.sh
# 选择选项 8: 运行完整集成测试
```

### 3.2 直接启动容器（开发调试）

```bash
# 启动所有服务（Kafka + ClickHouse + Filebeat）
docker compose -f tests/collectors/docker-compose-full.yml up -d

# 查看服务状态
docker compose -f tests/collectors/docker-compose-full.yml ps

# 查看 Filebeat 日志
docker logs filebeat

# 停止服务
docker compose -f tests/collectors/docker-compose-full.yml down
```

## 4. 安装步骤

> **注意**：自 v1.2.0 起，Filebeat 已容器化，无需在宿主机安装！

### 4.1 仅需安装 Docker 与 Docker Compose

```bash
curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh
sudo apt install docker-compose-plugin
sudo systemctl enable docker
sudo systemctl start docker

# 将用户加入 docker 组（避免 sudo）
sudo usermod -aG docker $USER
# 重新登录后生效
```

## 5. 采集器接口与使用方法

### 5.1 公共基类 `BaseCollector` 接口

所有采集器继承自 `BaseCollector`，提供以下核心接口：

| 方法                                     | 说明                                                         |
| ---------------------------------------- | ------------------------------------------------------------ |
| `start()`                                | 初始化连接（如 Kafka 消费者），设置 `is_running = True`      |
| `stop()`                                 | 关闭连接，设置 `is_running = False`                          |
| `collect() -> Generator[Dict, None, None]` | 生成器，持续 yield 日志字典，内部会调用 `validate_log` 和 `enrich_log` |
| `validate_log(log_data: Dict) -> bool`   | 验证日志是否包含 `timestamp`, `log_type`, `source`, `message` 且时间戳合法 |
| `enrich_log(log_data: Dict) -> Dict`     | 添加 `collector`, `collected_at`, `msg_id` 字段              |

### 5.2 `FilebeatCollector` 接口

**适用场景**：使用 Filebeat 采集系统日志、应用日志等，并推送到 Kafka。

**配置参数**：

| 参数                  | 默认值                   | 说明                              |
| --------------------- | ------------------------ | --------------------------------- |
| `kafka_topic`         | `logs_raw`               | 消费的 topic                      |
| `bootstrap_servers`   | `localhost:9092`         | Kafka broker 地址，多个用逗号分隔 |
| `group_id`            | `filebeat_collector`     | 消费者组 ID，用于 offset 管理     |

**使用示例**：

```python
from src.collectors.filebeat import FilebeatCollector

collector = FilebeatCollector(config={
    'bootstrap_servers': 'localhost:9092',
    'kafka_topic': 'logs_raw',
    'group_id': 'my_group'
})
collector.start()
for log in collector.collect():
    print(f"[{log['log_type']}] {log['message'][:50]}")
    if some_condition:
        break
collector.stop()
```

**输出字段**（经 `enrich_log` 后）：

| 字段           | 说明                                         |
| -------------- | -------------------------------------------- |
| `timestamp`    | 日志产生时间（优先取 `@timestamp`）          |
| `log_type`     | 从 `fields.log_type` 或根级 `log_type` 获取  |
| `source`       | 原始日志文件路径（`log.file.path` 或 `source`） |
| `message`      | 日志正文                                     |
| `host`         | 主机名（`host.name`）                        |
| `offset`       | Kafka 分区 offset                            |
| `partition`    | Kafka 分区号                                 |
| `collector`    | 固定为 `"filebeat"`                          |
| `collected_at` | 采集器收到消息的时间（ISO 格式）             |
| `msg_id`       | 基于内容生成的 MD5 哈希前 16 位              |

### 5.3 `FlumeCollector` 接口

**适用场景**：消费由 Flume 或其他自定义生产者发送的简单 JSON 日志（无需 Filebeat 的复杂元数据）。支持批量拉取，适合高吞吐场景。

**配置参数**：

| 参数                | 默认值               | 说明                                   |
| ------------------- | -------------------- | -------------------------------------- |
| `kafka_topic`       | `logs_raw`           | 消费的 topic                           |
| `bootstrap_servers` | `localhost:9092`     | Kafka broker 地址                      |
| `group_id`          | `flume_collector`    | 消费者组 ID                            |
| `batch_size`        | `100`                | 每次 poll 最大拉取的消息数（`max_poll_records`） |

**使用示例**：

```python
from src.collectors.flume import FlumeCollector

collector = FlumeCollector(config={
    'bootstrap_servers': 'localhost:9092',
    'kafka_topic': 'logs_raw',
    'group_id': 'flume_group',
    'batch_size': 200
})
collector.start()
for log in collector.collect():
    # 日志格式必须包含 timestamp, log_type, source, message 至少其一
    print(log)
collector.stop()
```

**输出字段**：

- 优先从原始 JSON 中提取 `timestamp`（若不存在则尝试 `@timestamp`）
- `log_type`：直接取根级 `log_type`，默认为 `"unknown"`
- `source`：直接取根级 `source`，默认为 `"flume"`
- `message`：直接取根级 `message`
- 原始 JSON 中的其他字段会合并到输出字典中（例如 `user`、`ip`、`action` 等）
- 额外添加 `offset`、`collector`、`collected_at`、`msg_id`

**批量处理接口**：

`FlumeCollector` 还提供了 `process_batch(logs: list)` 方法，可用于批量处理（例如写入数据库）。该方法不会被自动调用，需要你在外部显式调用：

```python
batch = []
for log in collector.collect():
    batch.append(log)
    if len(batch) >= 500:
        collector.process_batch(batch)   # 自定义批量处理
        batch.clear()
```

## 6. 常见问题

| 问题                                     | 解决方案                                                     |
| ---------------------------------------- | ------------------------------------------------------------ |
| Filebeat 报错 `lookup -localhost`        | 配置文件中不要使用 `${VAR:-default}` 语法，改用固定值。      |
| 权限错误 `permission denied`             | 不要用 `sudo` 运行 Filebeat，并确保 `filebeat_data` 目录可写。 |
| FlumeCollector 收不到消息                | 检查生产者发送的 JSON 是否包含 `timestamp`/`log_type`/`source`/`message` 字段，否则会被 `validate_log` 拒绝。 |
| 消费者 `group_id` 导致 offset 跳过       | 更换 `group_id` 或设置 `auto_offset_reset='earliest'`（代码中已设置）。 |
| 日志生成器不工作                         | 确认 `tests/collectors/sample_logs` 目录存在且可写，查看终端输出。 |
| Docker 权限问题                          | 将用户加入 docker 组：`sudo usermod -aG docker $USER`，然后重新登录。 |
| 运行集成测试时卡在 `开始从 Kafka 拉取日志...` | 检查 Filebeat 是否正常运行，`sample_logs` 目录是否有日志文件，Kafka 是否就绪。 |

## 7. 项目目录结构

```
Log_Analysis_AI_Assistant/
├── config/
│   └── filebeat.yml                     # 备用配置（宿主机部署）
├── tests/collectors/
│   ├── simulate_logs.py                 # 日志模拟器
│   ├── integration_test_collectors.py   # 集成测试
│   ├── sample_logs/                     # 日志生成目录
│   ├── docker-compose-full.yml          # Docker Compose 完整配置
│   └── filebeat-config.yml              # 容器化 Filebeat 配置
├── src/collectors/
│   ├── __init__.py
│   ├── base.py                          # 基类接口
│   ├── filebeat.py                      # FilebeatCollector 实现
│   └── flume.py                         # FlumeCollector 实现
├── logs/
│   └── filebeat/                        # Filebeat 容器日志目录
└── venv/                                # 虚拟环境
```

## 8. 注意事项

1. **路径问题**：所有相对路径都相对于项目根目录。
2. **容器化部署**：自 v1.2.0 起，Filebeat 已容器化，无需在宿主机安装。
3. **虚拟环境**：确保在运行脚本前激活虚拟环境（`source venv/bin/activate`）。
4. **Docker 权限**：确保用户有 Docker 执行权限（加入 `docker` 组）。
5. **测试顺序**：建议先确保 Docker 和 Kafka 正常运行，再执行集成测试。
6. **资源清理**：测试完成后及时清理 Docker 容器，避免占用资源。
7. **测试数据**：集成测试会自动生成硬编码的测试数据并在日志中显示，确保测试可验证。
8. **日志目录**：确保 `logs/filebeat/` 目录存在且可写。

## 9. 测试状态

- ✅ **采集器单元测试**: 通过
- ✅ **Kafka 集成测试**: 通过
- ✅ **容器化部署测试**: 通过
- ⏳ **端到端集成测试**: 进行中（日志生成 → Filebeat容器 → Kafka → 采集器 → ClickHouse）

## 10. 更新日志

### v1.2.0 (2026-05-13)
- ✅ 实现 Filebeat 容器化部署
- ✅ 更新 Docker Compose 配置，整合 Kafka、ClickHouse、Filebeat
- ✅ 修复容器启动顺序问题（Kafka 就绪后再启动 Filebeat）
- ✅ 修复 Filebeat 挂载目录权限问题
- ✅ 优化集成测试流程，支持容器化服务检测
