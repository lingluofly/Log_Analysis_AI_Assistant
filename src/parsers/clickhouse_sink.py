"""
ClickHouse 数据输出实现
实现 DataSink 接口，将结构化日志数据存入 ClickHouse
"""
import time
import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime

from .interfaces import DataSink
from ..storage.clickhouse import ClickHouseClient
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ClickHouseDataSink(DataSink):
    """
    ClickHouse 数据输出实现
    将解析后的日志数据插入到 ClickHouse 的 logs_structured 表
    """
    
    DEFAULT_TABLE = "logs_structured"
    
    STRUCTURED_TABLE_COLUMNS = [
        "id",
        "timestamp",
        "log_type",
        "source",
        "username",
        "user_id",
        "dept",
        "role",
        "action",
        "event_type",
        "result",
        "fail_reason",
        "source_ip",
        "destination_ip",
        "vpn_gateway",
        "src_country",
        "src_city",
        "protocol",
        "auth_method",
        "client_software",
        "user_agent",
        "session_id",
        "is_off_hours",
        "is_unusual_ip",
        "session_duration_sec",
        "bytes_sent",
        "bytes_recv",
        "risk_score",
        "risk_tags",
        "uri",
        "method",
        "status_code",
        "response_time",
        "detail",
        "severity_level",
        "device_info",
        "location",
        "request_id",
        "collected_at",
        "parsed_at",
        "indexed_at",
        "raw_log",
        "parser",
        "parse_status",
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, table: Optional[str] = None):
        """
        初始化 ClickHouse 数据输出
        
        Args:
            config: ClickHouse 连接配置
                - host: ClickHouse 服务器地址 (默认: localhost)
                - port: 端口 (默认: 8123)
                - username: 用户名 (默认: default)
                - password: 密码 (默认: 空)
                - database: 数据库名 (默认: log_analysis)
                - timeout: 超时时间 (默认: 30)
                - compress: 是否压缩 (默认: False)
            table: 目标表名 (默认: logs_structured)
        """
        self.config = config or {}
        self.table = table or self.DEFAULT_TABLE
        self.client: Optional[ClickHouseClient] = None
        self._id_counter = int(time.time() * 1000)
    
    def connect(self) -> bool:
        """
        连接到 ClickHouse
        
        Returns:
            连接是否成功
        """
        try:
            clickhouse_config = {
                'host': self.config.get('host', 'localhost'),
                'port': self.config.get('port', 8123),
                'username': self.config.get('username', 'default'),
                'password': self.config.get('password', ''),
                'database': self.config.get('database', 'log_analysis'),
                'timeout': self.config.get('timeout', 30),
                'compress': self.config.get('compress', False),
            }
            
            self.client = ClickHouseClient(clickhouse_config)
            self.client.connect()
            
            logger.info(f"ClickHouseDataSink 连接成功: {clickhouse_config['host']}:{clickhouse_config['port']}/{clickhouse_config['database']}")
            return True
            
        except Exception as e:
            logger.error(f"ClickHouseDataSink 连接失败: {e}")
            self.client = None
            return False
    
    def insert(self, data: List[Dict[str, Any]], table: Optional[str] = None) -> bool:
        """
        批量插入结构化日志数据
        
        Args:
            data: 解析后的日志数据列表
            table: 目标表名 (可选，默认使用初始化时的表名)
            
        Returns:
            插入是否成功
        """
        if not self.client:
            logger.error("ClickHouse 未连接，请先调用 connect()")
            return False
        
        if not data:
            logger.warning("收到空数据列表，跳过插入")
            return True
        
        target_table = table or self.table
        
        try:
            formatted_logs = []
            for log_entry in data:
                formatted = self._format_log_for_clickhouse(log_entry)
                if formatted:
                    formatted_logs.append(formatted)
            
            if not formatted_logs:
                logger.warning("所有日志格式化后为空，跳过插入")
                return False
            
            inserted_count = self.client.insert_logs(target_table, formatted_logs)
            
            logger.info(f"成功插入 {inserted_count} 条日志到 {target_table}")
            return True
            
        except Exception as e:
            logger.error(f"插入日志到 ClickHouse 失败: {e}")
            return False
    
    def _format_log_for_clickhouse(self, log_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        将解析后的日志数据格式化为 ClickHouse 表结构
        
        Args:
            log_data: 解析后的日志数据
            
        Returns:
            格式化后的日志数据，格式化失败返回 None
        """
        try:
            timestamp = log_data.get('timestamp')
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except Exception:
                    timestamp = datetime.now()
            elif not isinstance(timestamp, datetime):
                timestamp = datetime.now()
            
            collected_at = log_data.get('collected_at')
            if isinstance(collected_at, str):
                try:
                    collected_at = datetime.fromisoformat(collected_at.replace('Z', '+00:00'))
                except Exception:
                    collected_at = datetime.now()
            elif not isinstance(collected_at, datetime):
                collected_at = datetime.now()
            
            parsed_at = log_data.get('parsed_at', datetime.now())
            if isinstance(parsed_at, str):
                try:
                    parsed_at = datetime.fromisoformat(parsed_at.replace('Z', '+00:00'))
                except Exception:
                    parsed_at = datetime.now()
            elif not isinstance(parsed_at, datetime):
                parsed_at = datetime.now()
            
            status_code = log_data.get('status_code')
            if status_code is not None:
                try:
                    status_code = int(status_code)
                except (ValueError, TypeError):
                    status_code = None
            
            response_time = log_data.get('response_time')
            if response_time is not None:
                try:
                    response_time = float(response_time)
                except (ValueError, TypeError):
                    response_time = None
            
            formatted = {
                'id': self._generate_id(),
                'timestamp': timestamp,
                'log_type': log_data.get('log_type', 'application'),
                'source': log_data.get('source', 'parser'),
                'username': log_data.get('username', 'unknown'),
                'user_id': log_data.get('user_id'),
                'dept': log_data.get('dept'),
                'role': log_data.get('role'),
                'action': log_data.get('action', 'UNKNOWN'),
                'event_type': log_data.get('event_type'),
                'result': log_data.get('result'),
                'fail_reason': log_data.get('fail_reason'),
                'source_ip': log_data.get('source_ip'),
                'destination_ip': log_data.get('destination_ip'),
                'vpn_gateway': log_data.get('vpn_gateway'),
                'src_country': log_data.get('src_country'),
                'src_city': log_data.get('src_city'),
                'protocol': log_data.get('protocol'),
                'auth_method': log_data.get('auth_method'),
                'client_software': log_data.get('client_software'),
                'user_agent': log_data.get('user_agent'),
                'session_id': log_data.get('session_id'),
                'is_off_hours': log_data.get('is_off_hours'),
                'is_unusual_ip': log_data.get('is_unusual_ip'),
                'session_duration_sec': log_data.get('session_duration_sec'),
                'bytes_sent': log_data.get('bytes_sent'),
                'bytes_recv': log_data.get('bytes_recv'),
                'risk_score': log_data.get('risk_score'),
                'risk_tags': log_data.get('risk_tags'),
                'uri': log_data.get('uri'),
                'method': log_data.get('method'),
                'status_code': status_code,
                'response_time': response_time,
                'detail': log_data.get('detail'),
                'severity_level': log_data.get('severity_level'),
                'device_info': log_data.get('device_info'),
                'location': log_data.get('location'),
                'request_id': log_data.get('request_id'),
                'collected_at': collected_at,
                'parsed_at': parsed_at,
                'indexed_at': datetime.now(),
                'raw_log': log_data.get('raw_log'),
                'parser': log_data.get('parser'),
                'parse_status': log_data.get('parse_status'),
            }
            
            return formatted
            
        except Exception as e:
            logger.error(f"格式化日志数据失败: {e}")
            return None
    
    def _generate_id(self) -> int:
        """
        生成唯一的 UInt64 ID
        使用毫秒级时间戳 + 计数器确保唯一性
        """
        self._id_counter += 1
        return self._id_counter
    
    def close(self):
        """关闭 ClickHouse 连接"""
        if self.client:
            try:
                self.client.close()
                logger.info("ClickHouseDataSink 连接已关闭")
            except Exception as e:
                logger.error(f"关闭 ClickHouse 连接失败: {e}")
            finally:
                self.client = None
