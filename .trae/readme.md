# 日志分析 AI 助手 (Log Analysis AI Assistant)

构建一个日志分析 AI 助手，帮助安全人员快速分析系统日志并发现异常行为

## 项目背景

企业每天都会产生大量日志，包含但不限于：
1. VPN、OA 的登入登出日志
2. 各个业务系统的运行日志
3. API 调用日志
4. 操作系统日志
5. 各类安全设备日志等

在企业内网中，单纯的"登录失败"可能只是忘记密码，但"凌晨三点在异地 IP 连续尝试五个账号登录"则是典型的安全威胁。传统的 ELK 看板需要安全专家手工配置规则，而 UEBA（User and Entity Behavior Analytics）通过关注"人"的行为模式来发现异常。

本项目旨在利用 AI 的理解能力，将枯燥的统计异常（如：请求频率突增）转化为可理解的安全报告。

## 项目流程

![项目流程图](docs/项目流程图/80803580-3542-4636-a82e-e18cd2be98f5.png)

## 功能模块

### 1. 日志采集模块 (`src/collectors/`)
- **Filebeat 采集器**: 负责系统日志、应用日志的实时采集
- **Flume 采集器**: 负责批量日志数据的采集
- **采集配置管理**: 统一管理各类日志源的采集配置
- **增量采集**: 支持断点续传和增量日志采集

### 2. 日志解析模块 (`src/parsers/`)
- **正则解析器**: 基于正则表达式的日志解析
- **Logparser 解析器**: 集成 Logparser 进行日志解析
- **日志标准化**: 将不同格式的日志统一为标准格式
- **字段提取**: 提取关键字段（时间、用户名、行为、事件、IP 等）

### 3. 数据存储模块 (`src/storage/`)
- **Kafka 消息队列**: 日志数据的缓冲和流转
- **ClickHouse 存储**: 结构化日志数据的存储和查询
- **Elasticsearch 存储**: 日志检索和分析（可选）
- **数据分区策略**: 按时间、日志类型进行数据分区

### 4. 用户行为建模模块 (`src/behavior/`)
- **用户画像构建**: 统计每个用户的正常行为模式
  - 平均登录时间段
  - 平均 API 调用频率
  - 常用 IP 段和地理位置
  - 常用设备和浏览器
- **行为基线计算**: 动态计算用户行为基线
- **异常检测算法**: 基于统计学的异常检测

### 5. AI 智能分析模块 (`src/ai/`)
- **异常上下文提取**: 提取异常行为的关键上下文信息
- **威胁分类**: 识别攻击类型（账号接管、数据窃取等）
- **风险评级**: 给出风险等级（高、中、低）
- **处置建议**: 生成安全处置建议

### 6. 可视化展示模块 (`src/visualization/`)
- **实时日志流**: 实时展示日志数据
- **UEBA 异常用户排行**: 展示风险最高的用户
- **安全评分看板**: 展示整体安全态势
- **AI 处置建议展示**: 展示 AI 生成的处置建议

### 7. 自动化报告模块 (`src/reports/`)
- **日报生成**: 每日自动生成《安全态势简报》
- **周报生成**: 每周生成安全态势总结
- **高危用户报告**: 详细列出高危用户及行为
- **报告导出**: 支持 PDF、HTML、Markdown 格式

## 技术栈

- **语言**: Python 3.9+
- **日志处理与存储**: Flink + Kafka + ClickHouse/Elasticsearch
- **日志解析**: Regex (正则表达式), Logparser
- **AI 框架**: LangChain (用于构建分析链), OpenAI API / 阿里云通义千问 API
- **Web 展示**: Streamlit (快速构建可视化界面)
- **任务调度**: APScheduler / Celery
- **配置管理**: python-dotenv

## 项目结构

```
Log_Analysis_AI_Assistant/
├── README.md                 # 项目说明文档
├── requirements.txt          # Python 依赖包
├── .env.example             # 环境变量配置模板
├── .gitignore               # Git 忽略文件配置
├── src/                     # 源代码目录
│   ├── __init__.py
│   ├── main.py              # 主程序入口
│   ├── collectors/          # 日志采集模块
│   │   ├── __init__.py
│   │   ├── base.py          # 采集器基类
│   │   ├── filebeat.py      # Filebeat 采集器
│   │   └── flume.py         # Flume 采集器
│   ├── parsers/             # 日志解析模块
│   │   ├── __init__.py
│   │   ├── base.py          # 解析器基类
│   │   ├── regex_parser.py  # 正则解析器
│   │   └── logparser.py     # Logparser 解析器
│   ├── storage/             # 数据存储模块
│   │   ├── __init__.py
│   │   ├── kafka_client.py  # Kafka 客户端
│   │   ├── clickhouse.py    # ClickHouse 客户端
│   │   └── elasticsearch.py # Elasticsearch 客户端
│   ├── behavior/            # 用户行为建模模块
│   │   ├── __init__.py
│   │   ├── user_profile.py  # 用户画像
│   │   ├── baseline.py      # 行为基线
│   │   └── anomaly.py       # 异常检测
│   ├── ai/                  # AI 分析模块
│   │   ├── __init__.py
│   │   ├── analyzer.py      # AI 分析器
│   │   ├── threat_classifier.py  # 威胁分类器
│   │   └── prompt_templates.py   # Prompt 模板
│   ├── visualization/       # 可视化模块
│   │   ├── __init__.py
│   │   └── dashboard.py     # Streamlit 仪表板
│   ├── reports/             # 报告生成模块
│   │   ├── __init__.py
│   │   ├── daily_report.py  # 日报生成
│   │   └── weekly_report.py # 周报生成
│   └── utils/               # 工具类
│       ├── __init__.py
│       ├── config.py        # 配置管理
│       ├── logger.py        # 日志工具
│       └── helpers.py       # 辅助函数
├── config/                  # 配置文件目录
│   ├── filebeat.yml         # Filebeat 配置
│   ├── logstash.conf        # Logstash 配置
│   └── clickhouse.sql       # ClickHouse 表结构
├── tests/                   # 测试目录
│   ├── __init__.py
│   ├── test_collectors.py
│   ├── test_parsers.py
│   └── test_behavior.py
└── logs/                    # 运行日志目录
    └── .gitkeep
```

## 开发工作流

### 1. 环境初始化

```bash
# 1. 克隆项目
git clone <repository-url>
cd Log_Analysis_AI_Assistant

# 2. 创建虚拟环境
python -m venv venv

# 3. 激活虚拟环境
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. 安装依赖
pip install -r requirements.txt

# 5. 配置环境变量
cp .env.example .env
# 编辑.env 文件，填入必要的配置信息

# 6. 初始化数据库
# 执行 config/clickhouse.sql 创建表结构

# 7. 运行项目
python src/main.py
```

### 2. 开发规范

#### 代码风格
- 遵循 PEP 8 代码规范
- 使用 Black 进行代码格式化
- 使用 Flake8 进行代码检查

#### Git 工作流
```bash
# 1. 从主分支创建功能分支
git checkout -b feature/your-feature-name

# 2. 开发并提交
git add .
git commit -m "feat: add your feature description"

# 提交规范:
# feat: 新功能
# fix: 修复 bug
# docs: 文档更新
# style: 代码格式调整
# refactor: 代码重构
# test: 测试相关
# chore: 构建/工具链相关

# 3. 推送到远程
git push origin feature/your-feature-name

# 4. 创建 Pull Request
```

#### 分支管理
- `main`: 主分支，稳定版本
- `develop`: 开发分支，日常开发
- `feature/*`: 功能分支，开发新功能
- `bugfix/*`: 修复分支，修复 bug
- `release/*`: 发布分支，准备新版本

### 3. 模块开发流程

#### 开发新采集器
1. 在 `src/collectors/` 创建新的采集器文件
2. 继承 `BaseCollector` 基类
3. 实现 `collect()` 方法
4. 在配置文件中添加采集配置
5. 编写单元测试

#### 开发新解析器
1. 在 `src/parsers/` 创建新的解析器文件
2. 继承 `BaseParser` 基类
3. 实现 `parse()` 方法
4. 定义日志格式模式
5. 编写单元测试和样例日志

#### 开发 AI 分析功能
1. 在 `src/ai/` 创建分析器或更新现有分析器
2. 设计 Prompt 模板
3. 实现分析逻辑
4. 添加威胁分类规则
5. 编写测试用例

### 4. 测试流程

```bash
# 运行所有测试
pytest tests/

# 运行特定模块测试
pytest tests/test_collectors.py

# 生成测试覆盖率报告
pytest --cov=src tests/
```

### 5. 部署流程

#### 开发环境
```bash
python src/main.py
```

#### 生产环境
```bash
# 使用 Gunicorn 运行 Streamlit
streamlit run src/visualization/dashboard.py --server.port=8501

# 使用 Supervisor 管理进程
supervisorctl start log_analysis
```

## 配置说明

### 环境变量 (.env)

```ini
# AI API 配置
OPENAI_API_KEY=your_openai_api_key
OPENAI_API_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-3.5-turbo

# 或使用阿里云通义千问
DASHSCOPE_API_KEY=your_dashscope_api_key

# Kafka 配置
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_LOGS_TOPIC=logs_raw
KAFKA_ANALYZED_TOPIC=logs_analyzed

# ClickHouse 配置
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=8123
CLICKHOUSE_DATABASE=log_analysis
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=your_password

# Elasticsearch 配置 (可选)
ES_HOST=localhost
ES_PORT=9200
ES_INDEX=logs-*

# 日志采集配置
LOG_SOURCES_CONFIG=config/log_sources.yml

# 应用配置
LOG_LEVEL=INFO
REPORT_OUTPUT_DIR=reports/
```

### Filebeat 配置 (config/filebeat.yml)

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/syslog
    - /var/log/auth.log
  fields:
    log_type: system
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /var/log/nginx/access.log
  fields:
    log_type: nginx_access
  fields_under_root: true

output.kafka:
  hosts: ["localhost:9092"]
  topic: "logs_raw"
```

## 使用示例

### 1. 查看实时日志流

启动 Streamlit 应用后，在"实时日志流"页面可以查看实时流入的日志数据。

### 2. 查看异常用户排行

在"UEBA 异常排行"页面查看风险评分最高的用户列表。

### 3. 查看 AI 分析结果

点击具体用户，查看 AI 对该用户异常行为的分析结果和处置建议。

### 4. 获取日报

每日凌晨自动生成《安全态势简报》，可在 `reports/daily/` 目录查看。

## 常见问题

### Q: 如何添加新的日志源？
A: 在 `config/log_sources.yml` 中添加日志源配置，包括日志路径、格式类型、解析规则等。

### Q: 如何自定义异常检测规则？
A: 在 `src/behavior/anomaly.py` 中添加新的检测规则，或调整现有规则的阈值。

### Q: 如何更换 AI 模型？
A: 修改 `.env` 文件中的 AI 配置，支持 OpenAI、阿里云通义千问等多种模型。

### Q: 日志数据存储多久？
A: 默认存储 90 天，可在 ClickHouse 配置中调整数据保留策略。

## 贡献指南

1. Fork 本项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 许可证

MIT License

## 联系方式

如有问题或建议，请通过 Issue 反馈。
