"""ClickHouse 数据源到 behavior 的适配测试。"""

from datetime import datetime

import pytest

from src.behavior import api
from src.behavior.api import analyze_behavior_from_clickhouse
from src.behavior.repository import ClickHouseBehaviorDataError, structured_log_row_to_behavior_log


def test_structured_log_row_to_behavior_log_maps_fields() -> None:
    """结构化日志行应映射为 behavior 可消费字段。"""
    row = {
        "timestamp": datetime(2026, 5, 17, 10, 30, 0),
        "username": "zhangsan",
        "source_ip": "10.0.0.1",
        "src_city": "北京",
        "location": "上海",
        "action": "LOGIN",
        "event_type": "VPN_LOGIN",
        "result": "FAILED",
        "uri": "/login",
        "method": "POST",
        "risk_score": 0.8,
        "risk_tags": '["vpn"]',
        "raw_log": "raw",
    }

    result = structured_log_row_to_behavior_log(row)

    assert result["timestamp"] == "2026-05-17 10:30:00"
    assert result["status"] == "FAILED"
    assert result["location"] == "北京"
    assert result["endpoint"] == "/login"


def test_structured_log_row_to_behavior_log_falls_back_to_location() -> None:
    """src_city 缺失时应回退到 location。"""
    result = structured_log_row_to_behavior_log(
        {
            "timestamp": "2026-05-17 10:30:00",
            "username": "zhangsan",
            "location": "深圳",
            "result": "SUCCESS",
        }
    )

    assert result["location"] == "深圳"
    assert result["status"] == "SUCCESS"


def test_analyze_behavior_from_clickhouse_returns_stable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """repository 报错时 API 应返回稳定失败结构。"""
    def _raise(*args, **kwargs):
        raise ClickHouseBehaviorDataError("log_analysis.logs_structured 不存在")

    monkeypatch.setattr(api, "build_behavior_payload_from_clickhouse", _raise)

    result = analyze_behavior_from_clickhouse("zhangsan")

    assert result == {
        "success": False,
        "source": "clickhouse",
        "target_user": "zhangsan",
        "baseline": None,
        "profile": None,
        "anomalies": [],
        "summary": {
            "total_logs": 0,
            "anomaly_count": 0,
            "max_risk_score": 0,
            "overall_risk_level": "UNKNOWN",
        },
        "error": "log_analysis.logs_structured 不存在",
    }


def test_analyze_behavior_from_clickhouse_wraps_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """成功分析时应补充 clickhouse 来源标识。"""
    payload = {
        "target_user": "zhangsan",
        "history_logs": [
            {
                "timestamp": "2026-05-16 09:00:00",
                "username": "zhangsan",
                "source_ip": "10.0.0.1",
                "location": "北京",
                "action": "LOGIN",
                "status": "SUCCESS",
            }
        ],
        "detection_logs": [
            {
                "timestamp": "2026-05-17 22:00:00",
                "username": "zhangsan",
                "source_ip": "10.0.0.9",
                "location": "上海",
                "action": "LOGIN",
                "status": "FAILED",
            }
        ],
    }

    monkeypatch.setattr(api, "build_behavior_payload_from_clickhouse", lambda *args, **kwargs: payload)

    result = analyze_behavior_from_clickhouse("zhangsan")

    assert result["success"] is True
    assert result["source"] == "clickhouse"
    assert result["target_user"] == "zhangsan"
