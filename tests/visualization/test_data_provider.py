"""Tests for the visualization behavior data provider."""

from __future__ import annotations

import json
from pathlib import Path

from src.visualization.data_provider import DEFAULT_BEHAVIOR_PAYLOAD_PATH, get_dashboard_data


def _write_sample_payload(tmp_path: Path) -> str:
    payload = {
        "target_user": "zhangsan",
        "target_users": ["zhangsan", "lisi"],
        "history_logs": [
            {
                "id": 1,
                "timestamp": "2026-04-01 09:00:00",
                "username": "zhangsan",
                "source_ip": "10.0.0.1",
                "location": "北京",
                "action": "LOGIN_SUCCESS",
                "status": "SUCCESS",
            },
            {
                "id": 2,
                "timestamp": "2026-04-01 09:30:00",
                "username": "zhangsan",
                "source_ip": "10.0.0.1",
                "location": "北京",
                "action": "API_CALL",
                "endpoint": "/api/orders",
                "status": "SUCCESS",
            },
            {
                "id": 3,
                "timestamp": "2026-04-01 10:00:00",
                "username": "zhangsan",
                "source_ip": "10.0.0.1",
                "location": "北京",
                "action": "LOGIN_SUCCESS",
                "status": "SUCCESS",
            },
            {
                "id": 4,
                "timestamp": "2026-04-01 09:15:00",
                "username": "lisi",
                "source_ip": "10.0.1.1",
                "location": "上海",
                "action": "LOGIN_SUCCESS",
                "status": "SUCCESS",
            },
            {
                "id": 5,
                "timestamp": "2026-04-01 09:45:00",
                "username": "lisi",
                "source_ip": "10.0.1.1",
                "location": "上海",
                "action": "API_CALL",
                "endpoint": "/api/projects/list",
                "status": "SUCCESS",
            },
            {
                "id": 6,
                "timestamp": "2026-04-01 10:15:00",
                "username": "lisi",
                "source_ip": "10.0.1.1",
                "location": "上海",
                "action": "LOGIN_SUCCESS",
                "status": "SUCCESS",
            },
        ],
        "detection_logs": [
            {
                "id": 101,
                "timestamp": "2026-04-02 03:00:00",
                "username": "zhangsan",
                "source_ip": "8.8.8.8",
                "location": "广州",
                "action": "LOGIN_SUCCESS",
                "status": "SUCCESS",
            },
            {
                "id": 102,
                "timestamp": "2026-04-02 03:05:00",
                "username": "zhangsan",
                "source_ip": "8.8.4.4",
                "location": "广州",
                "action": "API_CALL",
                "endpoint": "/api/admin/export",
                "status": "SUCCESS",
            },
            {
                "id": 103,
                "timestamp": "2026-04-02 02:10:00",
                "username": "lisi",
                "source_ip": "203.0.113.10",
                "location": "深圳",
                "action": "LOGIN_SUCCESS",
                "status": "SUCCESS",
            },
            {
                "id": 104,
                "timestamp": "2026-04-02 02:15:00",
                "username": "lisi",
                "source_ip": "203.0.113.11",
                "location": "深圳",
                "action": "API_CALL",
                "endpoint": "/api/admin/export",
                "status": "SUCCESS",
            },
        ],
    }
    sample_path = tmp_path / "sample_logs.json"
    sample_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return str(sample_path)


def test_default_behavior_payload_path_uses_local_tox() -> None:
    assert DEFAULT_BEHAVIOR_PAYLOAD_PATH == ".tox/sample_logs.json"


def test_get_dashboard_data_returns_required_fields(tmp_path: Path) -> None:
    data = get_dashboard_data(_write_sample_payload(tmp_path))

    assert isinstance(data, dict)
    assert "summary" in data
    assert "risk_distribution" in data
    assert "anomaly_users" in data
    assert "anomaly_events" in data

    summary = data["summary"]
    assert "total_logs" in summary
    assert "anomaly_count" in summary
    assert "high_risk_users" in summary
    assert "security_score" in summary


def test_get_dashboard_data_uses_behavior_source_when_sample_logs_exist(tmp_path: Path) -> None:
    data = get_dashboard_data(_write_sample_payload(tmp_path))

    assert data["source"] == "behavior"
    assert data["success"] is True
    assert data["summary"]["total_logs"] > 0


def test_get_dashboard_data_returns_multiple_anomaly_users_when_target_users_exist(
    tmp_path: Path,
) -> None:
    data = get_dashboard_data(_write_sample_payload(tmp_path))

    usernames = {item["username"] for item in data["anomaly_users"]}
    assert len(usernames) >= 2
    assert "zhangsan" in usernames
    assert "lisi" in usernames


def test_get_dashboard_data_falls_back_to_mock_when_file_missing() -> None:
    data = get_dashboard_data(".tox/not_exists.json")

    assert data["source"] == "mock"
    assert data["success"] is False
