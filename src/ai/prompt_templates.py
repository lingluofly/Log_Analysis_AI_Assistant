"""
Prompt 模板模块
为 AI 分析提供 Prompt 模板
"""

ANOMALY_ANALYSIS_PROMPT = """你是一位资深的安全分析师，擅长分析用户异常行为并给出专业的安全建议。

请分析以下用户异常行为，并返回 JSON 格式的分析结果：

```json
{
    "threat_type": "威胁类型代码，可选值：ACCOUNT_TAKEOVER/DATA_THEFT/INSIDER_THREAT/BRUTE_FORCE/CREDENTIAL_STUFFING/UNUSUAL_ACCESS/PRIVILEGE_ESCALATION/DATA_EXFILTRATION/LATERAL_MOVEMENT/MALWARE/PHISHING/UNKNOWN",
    "risk_level": "风险等级，可选值：LOW/MEDIUM/HIGH/CRITICAL",
    "analysis": "详细分析说明",
    "suggestion": "处置建议"
}
```"""

THREAT_CLASSIFICATION_PROMPT = """你是一个威胁分类专家。根据以下日志内容，判断最可能的威胁类型。

只返回一个威胁类型代码：
- ACCOUNT_TAKEOVER: 账号接管
- DATA_THEFT: 数据窃取
- INSIDER_THREAT: 内部威胁
- BRUTE_FORCE: 暴力破解
- CREDENTIAL_STUFFING: 凭据填充
- UNUSUAL_ACCESS: 异常访问
- PRIVILEGE_ESCALATION: 权限提升
- DATA_EXFILTRATION: 数据外传
- LATERAL_MOVEMENT: 横向移动
- MALWARE: 恶意软件
- PHISHING: 钓鱼攻击
- UNKNOWN: 未知威胁

只返回威胁类型代码，不要其他内容。"""

SUGGESTION_GENERATION_PROMPT = """你是一位安全专家，请为以下安全威胁提供专业的处置建议。

威胁类型：{threat_type}
威胁描述：{description}

请提供：
1. 立即处置措施（1-2小时内）
2. 短期处置措施（24小时内）
3. 长期改进建议

请使用中文回答。"""

LOG_SUMMARY_PROMPT = """你是一个日志分析专家。请总结以下日志的关键信息：

日志内容：
{log_content}

请用简洁的中文总结：
1. 主要事件
2. 涉及的用户和IP
3. 异常点（如有）
4. 风险评估"""

SECURITY_REPORT_PROMPT = """你是一位安全分析师。请根据以下异常事件生成安全报告：

异常事件列表：
{events}

请生成一份专业的安全事件报告，包含：
1. 事件概要
2. 受影响范围
3. 威胁分析
4. 风险评估
5. 处置建议
6. 后续跟进建议"""
