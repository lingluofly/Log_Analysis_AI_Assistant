### AI API 使用手册

本项目支持多种 AI 平台，可根据需求选择合适的 API 服务。

---

## 支持的 AI 平台

### 1. 智谱AI (BigModel) - 推荐测试使用
**特点**: 提供免费额度，中文支持优秀
**模型**: glm-4-flash (免费), glm-4 (付费)
**官网**: https://open.bigmodel.cn/

**配置示例**:
```env
ZHIPU_API_KEY=your_api_key_here
ZHIPU_MODEL=glm-4-flash
ZHIPU_BASE_URL=https://open.bigmodel.cn/api/paas/v4/
AI_PLATFORM=zhipu
```

### 2. 硅基流动 (SiliconFlow) - 免费额度充足
**特点**: 提供免费额度，支持多种开源模型
**官网**: https://cloud.siliconflow.cn/

**配置示例**:
```env
SILICONFLOW_API_KEY=your_api_key_here
SILICONFLOW_MODEL=Qwen/Qwen2.5-7B-Instruct
AI_PLATFORM=siliconflow
```

### 3. Kimi (Moonshot AI) - 推荐生产使用
**特点**: 支持超长上下文，中文能力强
**官网**: https://platform.moonshot.cn/

**配置示例**:
```env
MOONSHOT_API_KEY=your_api_key_here
MOONSHOT_MODEL=kimi-k2.6
AI_PLATFORM=kimi
```

### 4. 阿里云百炼 (DashScope)
**特点**: 阿里云计算资源，支持通义千问系列模型
**官网**: https://dashscope.console.aliyun.com/

**配置示例**:
```env
DASHSCOPE_API_KEY=your_api_key_here
DASHSCOPE_MODEL=qwen-turbo
AI_PLATFORM=dashscope
```

### 5. OpenAI
**特点**: 行业标杆，英文能力强
**官网**: https://platform.openai.com/

**配置示例**:
```env
OPENAI_API_KEY=your_api_key_here
OPENAI_MODEL=gpt-3.5-turbo
AI_PLATFORM=openai
```

---

## 快速开始

1. **注册账号**: 选择一个 AI 平台注册并获取 API Key
2. **配置环境**: 在 `.env` 文件中填写 API Key 和平台选择
3. **安装依赖**: `pip install openai python-dotenv`
4. **运行测试**: `python tests/ai/test_ai_module.py`

---

## API 调用示例

```python
from openai import OpenAI

# 智谱AI示例
client = OpenAI(
    api_key="YOUR_ZHIPU_API_KEY",
    base_url="https://open.bigmodel.cn/api/paas/v4/"
)

completion = client.chat.completions.create(
    model="glm-4-flash",
    messages=[
        {"role": "system", "content": "你是一个安全日志分析助手。"},
        {"role": "user", "content": "分析以下日志：用户登录失败3次"}
    ]
)

print(completion.choices[0].message.content)
```

---

## 注意事项

- 所有平台 API 均为付费服务（部分提供免费试用额度）
- 注意保护 API Key，不要泄露到代码仓库
- 建议在测试环境使用免费额度，生产环境使用付费 API
- 不同平台的 API 格式完全兼容 OpenAI API