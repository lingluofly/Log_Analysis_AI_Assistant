"""
AI 分析器模块
实现日志异常分析、威胁分类、处置建议生成
"""
from typing import Any, Dict, List, Optional
import json
from .client import AIClient
from .prompt_templates import (
    ANOMALY_ANALYSIS_PROMPT,
    THREAT_CLASSIFICATION_PROMPT,
    SUGGESTION_GENERATION_PROMPT,
)
from .threat_classifier import ThreatClassifier

try:
    from ..utils.logger import get_logger
except ImportError:
    from utils.logger import get_logger

logger = get_logger(__name__)


class AIAnalyzer:
    """AI 分析器"""

    def __init__(
        self,
        api_key: str,
        platform: str = "kimi",
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        """
        初始化 AI 分析器

        Args:
            api_key: API 密钥
            platform: 平台类型 (openai/kimi/siliconflow/dashscope)
            model: 模型名称
            base_url: 自定义 API 地址
        """
        self.client = AIClient(
            api_key=api_key,
            platform=platform,
            model=model,
            base_url=base_url,
        )
        self.classifier = ThreatClassifier()

    def analyze_anomaly(
        self,
        username: str,
        anomaly_description: str,
        log_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        分析异常行为

        Args:
            username: 用户名
            anomaly_description: 异常行为描述
            log_context: 日志上下文（可选）

        Returns:
            分析结果字典，包含:
            - threat_type: 威胁类型
            - risk_level: 风险等级 (LOW/MEDIUM/HIGH/CRITICAL)
            - description: 分析描述
            - suggestion: 处置建议
        """
        user_message = f"用户：{username}\n异常行为描述：{anomaly_description}"
        if log_context:
            user_message += f"\n\n相关日志：\n{log_context}"

        system_prompt = ANOMALY_ANALYSIS_PROMPT.strip()

        try:
            response = self.client.analyze(
                system_prompt=system_prompt,
                user_message=user_message,
                temperature=0.3,
            )
            result = self._parse_json_response(response)

            if result:
                return {
                    "threat_type": result.get("threat_type", "UNKNOWN"),
                    "risk_level": result.get("risk_level", "MEDIUM"),
                    "description": result.get("analysis", result.get("description", "")),
                    "suggestion": result.get("suggestion", ""),
                }
        except Exception as e:
            logger.error(f"Failed to analyze anomaly: {e}")

        return {
            "threat_type": "UNKNOWN",
            "risk_level": "MEDIUM",
            "description": "AI 分析失败，请人工审查",
            "suggestion": "请人工审查该异常行为",
        }

    def classify_threat(self, log_content: str) -> str:
        """
        威胁分类

        Args:
            log_content: 日志内容

        Returns:
            威胁类型代码
        """
        system_prompt = THREAT_CLASSIFICATION_PROMPT.strip()

        try:
            response = self.client.analyze(
                system_prompt=system_prompt,
                user_message=f"日志内容：\n{log_content}",
                temperature=0.1,
            )
            threat_type = response.strip().upper()
            return self.classifier.normalize_threat_type(threat_type)
        except Exception as e:
            logger.error(f"Failed to classify threat: {e}")
            return "UNKNOWN"

    def generate_suggestion(
        self,
        threat_type: str,
        description: str,
    ) -> str:
        """
        生成处置建议

        Args:
            threat_type: 威胁类型
            description: 威胁描述

        Returns:
            处置建议
        """
        system_prompt = SUGGESTION_GENERATION_PROMPT.strip()

        try:
            return self.client.analyze(
                system_prompt=system_prompt,
                user_message=f"威胁类型：{threat_type}\n威胁描述：{description}",
                temperature=0.5,
            )
        except Exception as e:
            logger.error(f"Failed to generate suggestion: {e}")
            return "请人工审查并采取相应处置措施"

    def batch_analyze(
        self,
        anomalies: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        批量分析异常

        Args:
            anomalies: 异常列表，每个元素包含 username, description, log_context

        Returns:
            分析结果列表
        """
        results = []
        for anomaly in anomalies:
            result = self.analyze_anomaly(
                username=anomaly.get("username", "unknown"),
                anomaly_description=anomaly.get("description", ""),
                log_context=anomaly.get("log_context"),
            )
            results.append(result)
        return results

    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """
        解析 JSON 响应

        Args:
            response: AI 返回的原始响应

        Returns:
            解析后的字典，解析失败返回 None
        """
        try:
            response = response.strip()
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                response = response[start:end].strip()
            elif "```" in response:
                start = response.find("```") + 3
                end = response.find("```", start)
                response = response[start:end].strip()

            if response.startswith("{"):
                return json.loads(response)
        except json.JSONDecodeError:
            pass

        try:
            lines = response.split("\n")
            for line in lines:
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    return json.loads(line)
        except Exception:
            pass

        return None
