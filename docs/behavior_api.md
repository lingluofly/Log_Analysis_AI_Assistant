# Behavior API

## 接口用途

`src/behavior/api.py` 提供 `analyze_behavior_for_frontend(payload: dict) -> dict`，
用于给前端或其他模块提供统一、稳定的 Behavior 分析入口。

这个接口适配层只负责：

- 接收前端传入的 `dict/JSON`
- 校验 `target_user`、`history_logs`、`detection_logs`
- 调用现有 `BehaviorAnalysisService`
- 将内部结果转换为前端可直接使用的统一结构
- 在失败时返回固定错误对象，不暴露 Python traceback

## 输入 JSON 示例

```json
{
  "target_user": "zhangsan",
  "history_logs": [
    {
      "timestamp": "2026-04-01 09:00:00",
      "username": "zhangsan",
      "source_ip": "10.0.0.1",
      "location": "北京",
      "action": "LOGIN_SUCCESS",
      "endpoint": "/login",
      "status": "SUCCESS"
    }
  ],
  "detection_logs": [
    {
      "timestamp": "2026-04-02 23:30:00",
      "username": "zhangsan",
      "source_ip": "192.168.1.50",
      "location": "上海",
      "action": "LOGIN_FAILED",
      "endpoint": "/login",
      "status": "FAILED"
    }
  ]
}
```

## 成功返回示例

```json
{
  "success": true,
  "target_user": "zhangsan",
  "baseline": {
    "username": "zhangsan",
    "sample_count": 5
  },
  "profile": {
    "username": "zhangsan",
    "total_actions": 5
  },
  "anomalies": [
    {
      "timestamp": "2026-04-02 23:30:00",
      "username": "zhangsan",
      "anomaly_type": "unusual_location",
      "risk_score": 0.82,
      "risk_level": "high",
      "reason": "位置 上海 不在常用范围内"
    }
  ],
  "summary": {
    "total_logs": 2,
    "anomaly_count": 1,
    "max_risk_score": 0.82,
    "overall_risk_level": "high"
  },
  "error": null
}
```

## 失败返回示例

```json
{
  "success": false,
  "target_user": null,
  "baseline": {},
  "profile": {},
  "anomalies": [],
  "summary": {
    "total_logs": 0,
    "anomaly_count": 0,
    "max_risk_score": 0.0,
    "overall_risk_level": "unknown"
  },
  "error": {
    "code": "INVALID_INPUT",
    "message": "缺少 target_user"
  }
}
```

## 字段说明

- `success`: 是否分析成功
- `target_user`: 成功时返回目标用户，失败时固定为 `null`
- `baseline`: 内部行为基线结果
- `profile`: 内部用户画像结果
- `anomalies`: 前端友好的异常列表
- `summary.total_logs`: 本次请求收到并参与适配的历史日志数与检测日志数之和
- `summary.anomaly_count`: 异常数量
- `summary.max_risk_score`: 异常列表中的最大评分
- `summary.overall_risk_level`: `high` / `medium` / `low` / `unknown`
- `error.code`: 当前支持 `INVALID_INPUT`、`ANALYSIS_ERROR`
- `error.message`: 可直接展示给前端或用于日志记录的错误提示

## 前端对接注意事项

- `payload` 顶层必须是对象，且必须包含非空 `target_user`
- `history_logs`、`detection_logs` 缺省时会按空列表处理
- `history_logs`、`detection_logs` 必须是数组，传字符串等其他类型会返回 `INVALID_INPUT`
- 单条日志若缺少 `username`，接口会回退使用 `target_user`
- 单条日志若 `timestamp` 无法解析，不会导致整个接口崩溃；该日志只会在后续分析中被安全跳过或降级处理
