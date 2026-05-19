"""
威胁分类器模块
实现威胁分类逻辑，支持基于规则和 AI 辅助分类
"""
from typing import Any, Dict, List, Optional
import re

THREAT_TYPES = {
    "ACCOUNT_TAKEOVER": "账号接管",
    "DATA_THEFT": "数据窃取",
    "INSIDER_THREAT": "内部威胁",
    "BRUTE_FORCE": "暴力破解",
    "CREDENTIAL_STUFFING": "凭据填充",
    "UNUSUAL_ACCESS": "异常访问",
    "PRIVILEGE_ESCALATION": "权限提升",
    "DATA_EXFILTRATION": "数据外传",
    "LATERAL_MOVEMENT": "横向移动",
    "MALWARE": "恶意软件",
    "PHISHING": "钓鱼攻击",
    "UNKNOWN": "未知威胁",
}

RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

RULE_PATTERNS = {
    "BRUTE_FORCE": [
        r"failed.*login",
        r"authentication.*fail",
        r"invalid.*password",
        r"login.*attempt.*fail",
        r"wrong.*password",
        r"账号.*登录.*失败",
        r"密码.*错误",
    ],
    "CREDENTIAL_STUFFING": [
        r"multiple.*ip.*login",
        r"different.*location.*login",
        r"rapid.*login.*attempt",
        r"账号.*异地.*登录",
        r"短时间内.*多次.*登录",
    ],
    "UNUSUAL_ACCESS": [
        r"unusual.*time.*access",
        r"abnormal.*hours",
        r"off.*hours.*access",
        r"非工作时间.*访问",
        r"异常时间.*登录",
    ],
    "PRIVILEGE_ESCALATION": [
        r"sudo.*attempt",
        r"sudo.*命令",
        r"admin.*privilege",
        r"permission.*denied",
        r"access.*control.*bypass",
        r"权限.*提升",
        r"管理员.*操作",
        r"尝试.*sudo",
    ],
    "DATA_EXFILTRATION": [
        r"large.*download",
        r"bulk.*export",
        r"sensitive.*data.*access",
        r"data.*transfer.*abnormal",
        r"大量.*下载",
        r"敏感数据.*访问",
        r"数据.*外传",
    ],
    "ACCOUNT_TAKEOVER": [
        r"password.*changed",
        r"account.*locked",
        r"security.*question.*changed",
        r"账号.*锁定",
        r"密码.*被改",
    ],
}


class ThreatClassifier:
    """威胁分类器"""

    def __init__(self):
        """初始化分类器"""
        self.threat_types = THREAT_TYPES
        self.risk_levels = RISK_LEVELS
        self.rule_patterns = RULE_PATTERNS

    def classify(self, anomaly_data: Dict[str, Any]) -> str:
        """
        分类威胁类型（基于规则）

        Args:
            anomaly_data: 异常数据，包含 description, log_content 等

        Returns:
            威胁类型代码
        """
        description = anomaly_data.get("description", "").lower()
        log_content = anomaly_data.get("log_content", "").lower()
        combined_text = f"{description} {log_content}"

        for threat_type, patterns in self.rule_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    return threat_type

        return "UNKNOWN"

    def classify_with_ai(
        self,
        log_content: str,
        ai_result: Optional[str] = None,
    ) -> str:
        """
        结合 AI 结果进行分类

        Args:
            log_content: 日志内容
            ai_result: AI 分类结果

        Returns:
            威胁类型代码
        """
        if ai_result:
            return self.normalize_threat_type(ai_result)

        rule_result = self.classify({"log_content": log_content})
        if rule_result != "UNKNOWN":
            return rule_result

        return "UNKNOWN"

    def normalize_threat_type(self, threat_type: str) -> str:
        """
        标准化威胁类型

        Args:
            threat_type: 原始威胁类型

        Returns:
            标准化的威胁类型代码
        """
        threat_type = threat_type.upper().strip()

        type_mapping = {
            "ACCOUNT_TAKEOVER": "ACCOUNT_TAKEOVER",
            "ACCOUNT_TAKEOVER": "ACCOUNT_TAKEOVER",
            "DATA_THEFT": "DATA_THEFT",
            "INSIDER_THREAT": "INSIDER_THREAT",
            "BRUTE_FORCE": "BRUTE_FORCE",
            "CREDENTIAL_STUFFING": "CREDENTIAL_STUFFING",
            "UNUSUAL_ACCESS": "UNUSUAL_ACCESS",
            "ABNORMAL_ACCESS": "UNUSUAL_ACCESS",
            "PRIVILEGE_ESCALATION": "PRIVILEGE_ESCALATION",
            "DATA_EXFILTRATION": "DATA_EXFILTRATION",
            "LATERAL_MOVEMENT": "LATERAL_MOVEMENT",
            "MALWARE": "MALWARE",
            "PHISHING": "PHISHING",
            "钓鱼": "PHISHING",
            "暴力破解": "BRUTE_FORCE",
            "账号接管": "ACCOUNT_TAKEOVER",
            "数据窃取": "DATA_THEFT",
            "内部威胁": "INSIDER_THREAT",
            "权限提升": "PRIVILEGE_ESCALATION",
        }

        for key, value in type_mapping.items():
            if key in threat_type:
                return value

        for known_type in self.threat_types.keys():
            if known_type in threat_type:
                return known_type

        return "UNKNOWN"

    def get_threat_name(self, threat_code: str) -> str:
        """
        获取威胁类型中文名称

        Args:
            threat_code: 威胁类型代码

        Returns:
            中文名称
        """
        return self.threat_types.get(threat_code, "未知威胁")

    def assess_risk_level(
        self,
        threat_type: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        评估风险等级

        Args:
            threat_type: 威胁类型
            context: 上下文信息，包含频率、影响等

        Returns:
            风险等级 (LOW/MEDIUM/HIGH/CRITICAL)
        """
        base_levels = {
            "MALWARE": "CRITICAL",
            "ACCOUNT_TAKEOVER": "HIGH",
            "PRIVILEGE_ESCALATION": "HIGH",
            "DATA_EXFILTRATION": "HIGH",
            "LATERAL_MOVEMENT": "HIGH",
            "BRUTE_FORCE": "MEDIUM",
            "CREDENTIAL_STUFFING": "MEDIUM",
            "INSIDER_THREAT": "HIGH",
            "DATA_THEFT": "HIGH",
            "UNUSUAL_ACCESS": "LOW",
            "PHISHING": "MEDIUM",
            "UNKNOWN": "MEDIUM",
        }

        risk_level = base_levels.get(threat_type, "MEDIUM")

        if context:
            frequency = context.get("frequency", 0)
            if frequency > 10:
                risk_level = self._increase_risk_level(risk_level)

            is_sensitive_time = context.get("is_sensitive_time", False)
            if is_sensitive_time:
                risk_level = self._increase_risk_level(risk_level)

        return risk_level

    def _increase_risk_level(self, level: str) -> str:
        """增加风险等级"""
        level_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            current_index = level_order.index(level)
            if current_index < len(level_order) - 1:
                return level_order[current_index + 1]
        except ValueError:
            pass
        return level

    def batch_classify(
        self,
        anomalies: List[Dict[str, Any]],
    ) -> List[str]:
        """
        批量分类

        Args:
            anomalies: 异常数据列表

        Returns:
            威胁类型列表
        """
        return [self.classify(anomaly) for anomaly in anomalies]
