"""行为模块与存储层的协议定义。"""

import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Protocol

from src.behavior.normalizer import normalize_behavior_log, parse_timestamp_value
from src.storage.clickhouse import ClickHouseClient
from src.utils.helpers import format_datetime

from src.behavior.schemas import (
    AnomalyResult,
    BehaviorBaselineResult,
    NormalizedBehaviorLog,
    UserProfileResult,
)

try:
    from src.utils.logger import get_logger
except Exception:  # pragma: no cover - 兼容最小测试环境
    import logging

    def get_logger(name: str):
        return logging.getLogger(name)


logger = get_logger(__name__)


class BehaviorLogRepository(Protocol):
    """定义 behavior 对历史/实时日志的读取需求。

    真实实现应由 storage 模块或其适配层提供。
    """

    def fetch_user_history(
        self,
        username: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[NormalizedBehaviorLog]:
        """读取用户历史日志。"""

    def fetch_recent_user_events(
        self,
        username: str,
        window_minutes: int = 60,
        limit: Optional[int] = None,
    ) -> List[NormalizedBehaviorLog]:
        """读取用户近期窗口日志。"""


class BehaviorResultRepository(Protocol):
    """定义 behavior 对分析结果的写入需求。

    真实实现应由 storage 模块或其适配层提供。
    """

    def save_baseline(self, result: BehaviorBaselineResult) -> None:
        """保存行为基线。"""

    def save_profile(self, result: UserProfileResult) -> None:
        """保存用户画像。"""

    def save_anomalies(self, results: List[AnomalyResult]) -> None:
        """保存异常检测结果。"""


class InMemoryBehaviorRepository:
    """轻量内存仓储，便于本地演示和测试。"""

    def __init__(self, logs: Optional[List[NormalizedBehaviorLog]] = None) -> None:
        """初始化内存仓储。"""
        self._logs: List[NormalizedBehaviorLog] = []
        self.baselines: Dict[str, BehaviorBaselineResult] = {}
        self.profiles: Dict[str, UserProfileResult] = {}
        self.anomalies: List[AnomalyResult] = []
        if logs:
            self.add_logs(logs)

    def add_logs(self, logs: List[NormalizedBehaviorLog]) -> None:
        """批量写入内存日志。"""
        for log in logs:
            normalized = normalize_behavior_log(log)
            if normalized is not None:
                self._logs.append(normalized)
            else:
                logger.debug("内存仓储跳过无法标准化的日志")

    def fetch_user_history(
        self,
        username: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[NormalizedBehaviorLog]:
        """读取用户历史日志。"""
        results: List[NormalizedBehaviorLog] = []
        for log in self._logs:
            if log.get("username") != username:
                continue

            timestamp = parse_timestamp_value(log.get("timestamp"))
            if timestamp is None:
                continue
            if start_time is not None and timestamp < start_time:
                continue
            if end_time is not None and timestamp > end_time:
                continue
            results.append(dict(log))

        results.sort(key=lambda item: parse_timestamp_value(item.get("timestamp")) or datetime.max)
        if limit is not None:
            return results[:limit]
        return results

    def fetch_recent_user_events(
        self,
        username: str,
        window_minutes: int = 60,
        limit: Optional[int] = None,
    ) -> List[NormalizedBehaviorLog]:
        """读取用户近期窗口日志。"""
        history = self.fetch_user_history(username)
        if not history:
            return []

        latest_timestamp = max(
            parse_timestamp_value(log.get("timestamp")) or datetime.min
            for log in history
        )
        start_time = latest_timestamp - timedelta(minutes=window_minutes)
        recent = [
            log
            for log in history
            if (parse_timestamp_value(log.get("timestamp")) or datetime.min) >= start_time
        ]
        if limit is not None:
            return recent[-limit:]
        return recent

    def save_baseline(self, result: BehaviorBaselineResult) -> None:
        """保存行为基线。"""
        self.baselines[result["username"]] = dict(result)

    def save_profile(self, result: UserProfileResult) -> None:
        """保存用户画像。"""
        self.profiles[result["username"]] = dict(result)

    def save_anomalies(self, results: List[AnomalyResult]) -> None:
        """保存异常检测结果。"""
        self.anomalies.extend(dict(result) for result in results)


class ClickHouseBehaviorDataError(Exception):
    """ClickHouse 行为分析数据源错误。"""


def structured_log_row_to_behavior_log(row: Dict[str, Any]) -> Dict[str, Any]:
    """将 ``logs_structured`` 行转换为 behavior 可消费的日志结构。"""
    if not isinstance(row, dict):
        raise ClickHouseBehaviorDataError("logs_structured 行数据必须是 dict")

    timestamp = row.get("timestamp")
    if isinstance(timestamp, datetime):
        timestamp = format_datetime(timestamp)

    location = row.get("src_city") or row.get("location")
    behavior_log: Dict[str, Any] = {
        "timestamp": timestamp,
        "username": row.get("username"),
        "source_ip": row.get("source_ip"),
        "location": location,
        "action": row.get("action"),
        "event_type": row.get("event_type"),
        "status": row.get("result"),
        "endpoint": row.get("uri"),
        "method": row.get("method"),
        "risk_score": row.get("risk_score"),
        "risk_tags": row.get("risk_tags"),
        "raw_log": row.get("raw_log"),
    }
    return {key: value for key, value in behavior_log.items() if value not in (None, "")}


def build_behavior_payload_from_clickhouse(
    target_user: str,
    client_config: Optional[Dict[str, Any]] = None,
    history_days: int = 30,
    detection_hours: int = 24,
    limit: int = 1000,
) -> Dict[str, Any]:
    """从 ClickHouse 读取用户日志并组装 behavior payload。"""
    if not str(target_user).strip():
        raise ClickHouseBehaviorDataError("target_user 不能为空")

    config = client_config or _default_clickhouse_config()
    client = ClickHouseClient(config)
    database = str(config.get("database") or "log_analysis")

    try:
        client.connect()
        if client.client is None:
            raise ClickHouseBehaviorDataError("ClickHouse 连接未初始化")
        if not _table_exists(client, database, "logs_structured"):
            raise ClickHouseBehaviorDataError(f"{database}.logs_structured 不存在")

        now = datetime.now()
        history_start = now - timedelta(days=history_days)
        detection_start = now - timedelta(hours=detection_hours)
        history_rows = _query_structured_logs(
            client,
            database=database,
            target_user=target_user,
            start_time=history_start,
            end_time=detection_start,
            limit=limit,
        )
        detection_rows = _query_structured_logs(
            client,
            database=database,
            target_user=target_user,
            start_time=detection_start,
            end_time=now,
            limit=limit,
        )

        if not history_rows:
            raise ClickHouseBehaviorDataError("目标用户无历史日志")
        if not detection_rows:
            raise ClickHouseBehaviorDataError("目标用户无检测日志")

        return {
            "target_user": str(target_user).strip(),
            "history_logs": [structured_log_row_to_behavior_log(row) for row in history_rows],
            "detection_logs": [structured_log_row_to_behavior_log(row) for row in detection_rows],
        }
    except ClickHouseBehaviorDataError:
        raise
    except Exception as exc:
        raise ClickHouseBehaviorDataError(f"ClickHouse 查询失败: {exc}") from exc
    finally:
        client.close()


def _default_clickhouse_config() -> Dict[str, Any]:
    """读取环境变量生成 ClickHouse 客户端配置。"""
    return {
        "host": os.getenv("CLICKHOUSE_HOST", "localhost"),
        "port": int(os.getenv("CLICKHOUSE_PORT", "8123")),
        "username": os.getenv("CLICKHOUSE_USER", "default"),
        "password": os.getenv("CLICKHOUSE_PASSWORD", ""),
        "database": os.getenv("CLICKHOUSE_DATABASE", "log_analysis"),
    }


def _table_exists(client: ClickHouseClient, database: str, table: str) -> bool:
    """检查指定 ClickHouse 表是否存在。"""
    if client.client is None:
        return False
    result = client.client.query(
        """
        SELECT count()
        FROM system.tables
        WHERE database = %(database)s AND name = %(table)s
        """,
        parameters={"database": database, "table": table},
    )
    return bool(result.result_rows and int(result.result_rows[0][0]) > 0)


def _query_structured_logs(
    client: ClickHouseClient,
    database: str,
    target_user: str,
    start_time: datetime,
    end_time: datetime,
    limit: int,
) -> List[Dict[str, Any]]:
    """按时间窗口读取用户结构化日志。"""
    if client.client is None:
        raise ClickHouseBehaviorDataError("ClickHouse 连接未初始化")
    query = f"""
        SELECT *
        FROM {database}.logs_structured
        WHERE username = %(username)s
          AND timestamp >= %(start_time)s
          AND timestamp <= %(end_time)s
        ORDER BY timestamp ASC
        LIMIT %(limit)s
    """
    result = client.client.query(
        query,
        parameters={
            "username": target_user,
            "start_time": start_time,
            "end_time": end_time,
            "limit": limit,
        },
    )
    return [dict(zip(result.column_names, row)) for row in result.result_rows]
