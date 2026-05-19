"""
AI API 客户端模块
支持多平台：OpenAI、Kimi（Moonshot AI）、硅基流动、阿里云百炼
"""
from typing import Optional, Dict, Any, List
from openai import OpenAI

try:
    from ..utils.logger import get_logger
except ImportError:
    from utils.logger import get_logger

logger = get_logger(__name__)


class AIClient:
    """AI API 客户端，支持多平台适配"""

    SUPPORTED_PLATFORMS = {
        "openai": {
            "base_url": "https://api.openai.com/v1",
            "default_model": "gpt-3.5-turbo",
        },
        "kimi": {
            "base_url": "https://api.moonshot.cn/v1",
            "default_model": "kimi-k2.6",
        },
        "siliconflow": {
            "base_url": "https://api.siliconflow.cn/v1",
            "default_model": "Qwen/Qwen2.5-7B-Instruct",
        },
        "dashscope": {
            "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
            "default_model": "qwen-turbo",
        },
        "zhipu": {
            "base_url": "https://open.bigmodel.cn/api/paas/v4/",
            "default_model": "glm-4-flash",
        },
    }

    def __init__(
        self,
        api_key: str,
        platform: str = "openai",
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        """
        初始化 AI 客户端

        Args:
            api_key: API 密钥
            platform: 平台类型 (openai/kimi/siliconflow/dashscope)
            model: 模型名称，默认使用平台默认模型
            base_url: 自定义 API 地址
        """
        self.api_key = api_key
        self.platform = platform.lower()

        if self.platform not in self.SUPPORTED_PLATFORMS and not base_url:
            raise ValueError(f"Unsupported platform: {platform}")

        platform_config = self.SUPPORTED_PLATFORMS.get(self.platform, {})
        self.base_url = base_url or platform_config.get("base_url", "")
        self.default_model = platform_config.get("default_model", "gpt-3.5-turbo")
        self.model = model or self.default_model

        self.client = OpenAI(api_key=api_key, base_url=self.base_url)
        logger.info(f"AI Client initialized: platform={platform}, model={self.model}")

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        发送对话请求

        Args:
            messages: 消息列表，格式为 [{"role": "user/assistant/system", "content": "..."}]
            model: 模型名称
            temperature: 温度参数
            max_tokens: 最大 token 数

        Returns:
            AI 回复内容
        """
        try:
            response = self.client.chat.completions.create(
                model=model or self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            content = response.choices[0].message.content
            logger.debug(f"AI response: {content[:100]}...")
            return content
        except Exception as e:
            logger.error(f"AI API call failed: {e}")
            raise

    def analyze(
        self,
        system_prompt: str,
        user_message: str,
        temperature: float = 0.3,
    ) -> str:
        """
        快捷分析接口

        Args:
            system_prompt: 系统提示词
            user_message: 用户消息
            temperature: 温度参数（分析任务通常较低）

        Returns:
            AI 分析结果
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]
        return self.chat(messages, temperature=temperature)


def create_ai_client(
    api_key: str,
    platform: str = "kimi",
    model: Optional[str] = None,
    base_url: Optional[str] = None,
) -> AIClient:
    """
    工厂函数：创建 AI 客户端

    Args:
        api_key: API 密钥
        platform: 平台类型
        model: 模型名称
        base_url: 自定义 API 地址

    Returns:
        AIClient 实例
    """
    return AIClient(api_key=api_key, platform=platform, model=model, base_url=base_url)
