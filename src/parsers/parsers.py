"""
日志解析器集合

包含所有日志解析器实现：
- BaseParser: 解析器基类
- JSONParser: JSON 格式日志解析
- RegexParser: 正则表达式日志解析
- LogparserParser: INI 配置驱动的日志解析
- StandardLogSchema: 标准日志 Schema 定义
- FieldExtractor: 字段提取器
- 解析方案选择器：create_parser()

"""
import json
import re
import configparser
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime

from ..utils.logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# 解析器基类
# ============================================================================

class BaseParser(ABC):
    """日志解析器基类"""
    
    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        """
        初始化解析器
        
        Args:
            name: 解析器名称
            config: 配置字典
        """
        self.name = name
        self.config = config or {}
        
    @abstractmethod
    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        """
        解析单条日志
        
        Args:
            raw_log: 原始日志字符串
            
        Returns:
            解析后的字典，解析失败返回 None
        """
        pass
    
    def parse_batch(self, raw_logs: List[str]) -> List[Dict[str, Any]]:
        """
        批量解析日志
        
        Args:
            raw_logs: 原始日志列表
            
        Returns:
            解析后的字典列表
        """
        results = []
        for raw_log in raw_logs:
            parsed = self.parse(raw_log)
            if parsed:
                results.append(parsed)
        return results
    
    def validate_parsed(self, parsed_data: Dict[str, Any]) -> bool:
        """
        验证解析结果
        
        Args:
            parsed_data: 解析后的数据
            
        Returns:
            是否有效
        """
        return 'timestamp' in parsed_data
    
    def normalize_fields(self, log_data: Dict[str, Any], field_mappings: Dict[str, str]) -> Dict[str, Any]:
        """
        标准化字段名称
        
        Args:
            log_data: 原始解析数据
            field_mappings: 字段映射关系 {目标字段：源字段}
            
        Returns:
            标准化后的数据
        """
        result = {}
        for target_field, source_field in field_mappings.items():
            result[target_field] = log_data.get(source_field)
        return result


# ============================================================================
# 日志 Schema 定义
# ============================================================================

class LogSeverity(Enum):
    """日志严重程度"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogType(Enum):
    """日志类型"""
    VPN = "vpn"
    OA = "oa"
    API = "api"
    SYSTEM = "system"
    SECURITY = "security"
    APPLICATION = "application"
    NETWORK = "network"
    DATABASE = "database"


class ActionType(Enum):
    """常见行为类型"""
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    API_CALL = "API_CALL"
    FILE_ACCESS = "FILE_ACCESS"
    DATA_EXPORT = "DATA_EXPORT"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    NETWORK_ACCESS = "NETWORK_ACCESS"
    UNKNOWN = "UNKNOWN"


class StandardLogSchema:
    """
    标准日志 Schema 定义
    将所有日志统一转换为标准格式，支持用户行为分析和风险分析
    
    字段分类：
    1. 核心标识字段（必填）：唯一标识一条日志
    2. 5W1H行为分析字段：Who/What/When/Where/Why/How
    3. 用户行为基线字段：用于判断行为是否异常
    4. 风险分析字段：风险评分和标签
    5. 系统时间字段：日志生命周期时间戳
    6. 扩展字段：原始日志和解析信息
    """
    
    REQUIRED_FIELDS = [
        "timestamp",             # When: 日志生成时间
        "log_type",              # 日志类型
        "username",              # Who: 用户名
        "action",                # What: 行为动作
        "source_ip",             # Where: 来源IP
    ]
    
    OPTIONAL_FIELDS = [
        # === 5W1H 行为分析字段 ===
        "user_id",               # Who: 用户ID
        "dept",                  # Who: 部门
        "role",                  # Who: 角色
        "event_type",            # What: 事件类型
        "result",                # What: 结果
        "fail_reason",           # Why: 失败原因
        "destination_ip",        # Where: 目标IP
        "vpn_gateway",           # Where: 接入网关
        "src_country",           # Where: 来源国家
        "src_city",              # Where: 来源城市
        "protocol",              # How: 协议
        "auth_method",           # How: 认证方式
        "client_software",       # How: 客户端
        "session_id",            # How: 会话ID
        
        # === 用户行为基线字段 ===
        "is_off_hours",          # 是否非工作时间
        "is_unusual_ip",         # 是否异常IP
        "session_duration_sec",  # 会话时长
        "bytes_sent",            # 发送字节
        "bytes_recv",            # 接收字节
        
        # === 风险分析字段 ===
        "risk_score",            # 风险评分 0-100
        "risk_tags",             # 风险标签
        
        # === 通用扩展字段 ===
        "user_agent",
        "uri",
        "method",
        "status_code",
        "response_time",
        "detail",
        "severity_level",
        "device_info",
        "location",
        "request_id",
        
        # === 系统时间字段 ===
        "collected_at",          # 日志采集时间
        "parsed_at",             # 日志解析时间
        "indexed_at",            # 日志入库时间
        
        # === 原始数据 ===
        "raw_log",               # 原始日志
        "parser",                # 解析器
        "parse_status",          # 解析状态
    ]
    
    FIELD_TYPES = {
        "id": int,
        "timestamp": datetime,
        "log_type": str,
        "username": str,
        "user_id": str,
        "action": str,
        "event_type": str,
        "source_ip": str,
        "destination_ip": str,
        "user_agent": str,
        "uri": str,
        "method": str,
        "status_code": int,
        "response_time": float,
        "detail": str,
        "severity_level": str,
        "device_info": str,
        "location": str,
        "session_id": str,
        "request_id": str,
        "raw_log": str,
        "parser": str,
        "parse_status": str,
        "collected_at": datetime,
        "parsed_at": datetime,
    }
    
    LOG_TYPE_MAPPINGS = {
        "vpn": ["vpn", "fortinet", "cisco_vpn", "anyconnect"],
        "oa": ["oa", "workflow", "审批", "办公"],
        "api": ["api", "rest", "graphql", "webservice"],
        "system": ["syslog", "windows_event", "auth", "secure"],
        "security": ["firewall", "ids", "ips", "waf", "antivirus"],
        "application": ["app", "service", "daemon"],
        "network": ["nginx", "apache", "proxy", "loadbalancer"],
        "database": ["mysql", "postgresql", "oracle", "mongodb"],
    }
    
    ACTION_MAPPINGS = {
        "LOGIN": ["login", "登入", "authenticate", "auth_success", "登录成功"],
        "LOGOUT": ["logout", "登出", "signout", "session_end"],
        "API_CALL": ["api_call", "request", "http_request", "rpc_call"],
        "FILE_ACCESS": ["file_access", "read", "write", "download", "upload"],
        "DATA_EXPORT": ["export", "download", "batch_download"],
        "CONFIG_CHANGE": ["config_change", "modify", "update_config"],
        "PERMISSION_CHANGE": ["permission_change", "grant", "revoke", "role_change"],
        "NETWORK_ACCESS": ["network_access", "connect", "disconnect"],
    }
    
    @classmethod
    def create_standard_log(
        cls,
        timestamp: datetime,
        log_type: str,
        username: str,
        action: str,
        source_ip: str,
        **kwargs
    ) -> Dict[str, Any]:
        """创建标准格式的日志字典"""
        standard_log = {
            "timestamp": timestamp,
            "log_type": log_type,
            "username": username,
            "action": action,
            "source_ip": source_ip,
        }
        
        for field in cls.OPTIONAL_FIELDS:
            if field in kwargs:
                standard_log[field] = kwargs[field]
        
        if "parse_status" not in standard_log:
            standard_log["parse_status"] = "success"
        
        if "parsed_at" not in standard_log:
            standard_log["parsed_at"] = datetime.now()
        
        if "collected_at" not in standard_log:
            standard_log["collected_at"] = datetime.now()
        
        return standard_log
    
    @classmethod
    def normalize_log_type(cls, raw_log_type: str) -> str:
        """标准化日志类型"""
        raw_log_type_lower = raw_log_type.lower()
        
        for standard_type, keywords in cls.LOG_TYPE_MAPPINGS.items():
            for keyword in keywords:
                if keyword in raw_log_type_lower:
                    return standard_type
        
        return "application"
    
    @classmethod
    def normalize_action(cls, raw_action: str) -> str:
        """标准化行为动作"""
        raw_action_lower = raw_action.lower()
        
        for standard_action, keywords in cls.ACTION_MAPPINGS.items():
            for keyword in keywords:
                if keyword in raw_action_lower:
                    return standard_action
        
        return "UNKNOWN"
    
    @classmethod
    def validate_log(cls, log_data: Dict[str, Any]) -> bool:
        """验证日志数据是否符合标准"""
        for field in cls.REQUIRED_FIELDS:
            if field not in log_data or log_data[field] is None:
                return False
        
        if not isinstance(log_data["timestamp"], datetime):
            return False
        
        import re as re_module
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if log_data.get("source_ip") and not re_module.match(ip_pattern, log_data["source_ip"]):
            return False
        
        return True
    
    @classmethod
    def to_json(cls, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """转换为 JSON 可序列化格式"""
        result = log_data.copy()
        
        for field, value in result.items():
            if isinstance(value, datetime):
                result[field] = value.isoformat()
            elif isinstance(value, Enum):
                result[field] = value.value
        
        return result


# ============================================================================
# JSON 解析器
# ============================================================================

class JSONParser(BaseParser):
    """JSON 日志解析器"""
    
    def __init__(self, name: str = "json", config: Optional[Dict[str, Any]] = None):
        """初始化 JSON 解析器"""
        super().__init__(name, config)
        self.field_mappings = self.config.get('field_mappings', {})
        
    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        """解析 JSON 格式日志"""
        try:
            parsed_data = json.loads(raw_log.strip())
            
            if self.field_mappings:
                parsed_data = self.normalize_fields(parsed_data, self.field_mappings)
            
            parsed_data['raw_log'] = raw_log
            parsed_data['parser'] = self.name
            parsed_data['parse_status'] = 'success'
            
            return parsed_data
        except json.JSONDecodeError as e:
            logger.debug(f"JSON 解析失败：{e}")
            return None
        except Exception as e:
            logger.error(f"解析 JSON 日志失败：{e}")
            return None
    
    def set_field_mappings(self, mappings: Dict[str, str]):
        """设置字段映射"""
        self.field_mappings = mappings
        logger.info(f"JSON 解析器 [{self.name}] 字段映射已更新")


# ============================================================================
# 正则解析器
# ============================================================================

class RegexParser(BaseParser):
    """正则表达式日志解析器"""
    
    def __init__(self, name: str = "regex", config: Optional[Dict[str, Any]] = None):
        """初始化正则解析器"""
        super().__init__(name, config)
        self.pattern = self.config.get('pattern')
        self.compiled_pattern = None
        self.log_type = self.config.get('log_type', 'application')
        
        if self.pattern:
            try:
                self.compiled_pattern = re.compile(self.pattern)
                logger.info(f"正则解析器 [{self.name}] 编译成功")
            except re.error as e:
                logger.error(f"正则表达式编译失败：{e}")
                raise
    
    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        """使用正则表达式解析日志"""
        if not self.compiled_pattern:
            logger.error("正则表达式未编译")
            return None
        
        try:
            match = self.compiled_pattern.match(raw_log.strip())
            if match:
                parsed_data = match.groupdict()
                
                extracted = FieldExtractor.extract_all_fields(parsed_data)
                
                if extracted.get('timestamp') and (extracted.get('username') or extracted.get('source_ip') or extracted.get('action')):
                    standard_log = StandardLogSchema.create_standard_log(
                        timestamp=extracted['timestamp'],
                        log_type=self.log_type,
                        username=extracted['username'] or 'unknown',
                        action=extracted['action'] or 'UNKNOWN',
                        source_ip=extracted['source_ip'],
                        **{k: v for k, v in {
                            'destination_ip': extracted.get('destination_ip'),
                            'user_agent': parsed_data.get('user_agent'),
                            'uri': parsed_data.get('uri'),
                            'method': parsed_data.get('method'),
                            'status_code': parsed_data.get('status'),
                            'detail': parsed_data.get('message'),
                        }.items() if v is not None}
                    )
                    standard_log['raw_log'] = raw_log
                    standard_log['parser'] = self.name
                    return standard_log
                else:
                    parsed_data['raw_log'] = raw_log
                    parsed_data['parser'] = self.name
                    parsed_data['parse_status'] = 'partial'
                    return parsed_data
            else:
                logger.debug(f"日志不匹配正则模式：{raw_log[:100]}")
                return None
        except Exception as e:
            logger.error(f"解析日志失败：{e}")
            return None
    
    def update_pattern(self, new_pattern: str):
        """更新正则表达式"""
        try:
            self.compiled_pattern = re.compile(new_pattern)
            self.pattern = new_pattern
            logger.info(f"正则解析器 [{self.name}] 模式已更新")
        except re.error as e:
            logger.error(f"新正则表达式无效：{e}")
            raise


COMMON_PATTERNS = {
    'nginx_access': r'^(?P<remote_addr>[\d.]+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<body_bytes_sent>\d+)\s+"(?P<http_referer>[^"]*)"\s+"(?P<http_user_agent>[^"]*)"',
    'syslog': r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<program>\S+?)(\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$',
    'vpn_login': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<action>LOGIN|LOGOUT)\s+user=(?P<username>\w+)\s+ip=(?P<source_ip>[\d.]+)\s+status=(?P<status>\w+)',
    'vpn_gateway': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<vpn_gateway>\S+)\s+vpnd:\s+event=(?P<event_type>\S+)\s+user=(?P<username>\S+)\s+dept=(?P<dept>\S+)\s+src_ip=(?P<src_ip>[\d.]+)\s+src_geo=(?P<src_country>[^/]+)/(?P<src_city>\S+)\s+proto=(?P<protocol>\S+)\s+auth=(?P<auth_method>\S+)\s+client="(?P<client_software>[^"]+)"\s+session=(?P<session_id>\S+)\s+result=(?P<result>\S+)(?:\s+reason=(?P<fail_reason>[^ ]+))?(?:\s+duration=(?P<duration>\d+)s)?(?:\s+bytes_recv=(?P<bytes_recv>\d+))?(?:\s+bytes_sent=(?P<bytes_sent>\d+))?\s+risk_score=(?P<risk_score>\d+)\s+risk_tags="(?P<risk_tags>[^"]*)"',
    'fortinet_vpn': r'^date=(?P<timestamp>\d{4}-\d{2}-\d{2})\s+time=(?P<time>\d{2}:\d{2}:\d{2})\s+logid=\d+\s+type=event\s+subtype=vpn\s+level=notice\s+vd=root\s+user=(?P<username>\S+)\s+group=\S+\s+srcip=(?P<source_ip>[\d.]+)\s+action=(?P<action>ssl-login|ssl-logout)',
    'oa_system': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+user:(?P<username>\w+)\s+action:(?P<action>\w+)\s+module:(?P<module>\w+)\s+(?P<detail>.*)$',
    'api_call': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<uri>/\S+)\s+user=(?P<username>\S+)\s+status=(?P<status>\d+)\s+response_time=(?P<response_time>[\d.]+)ms',
    'windows_event': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<event_id>\d+)\s+(?P<level>\w+)\s+(?P<source>\S+)\s+(?P<message>.*)$',
    'database_query': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+user=(?P<username>\w+)\s+host=(?P<source_ip>[\d.]+)\s+query=(?P<query>.*)$',
    'firewall': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<action>ALLOW|DENY|DROP)\s+(?P<protocol>TCP|UDP|ICMP)\s+(?P<source_ip>[\d.]+):(?P<source_port>\d+)\s+->\s+(?P<destination_ip>[\d.]+):(?P<destination_port>\d+)',
    'linux_auth': r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*(?:Accepted|Failed)\s+(?:password|publickey)\s+for\s+(?P<username>\w+)\s+from\s+(?P<source_ip>[\d.]+).*)',
}


# ============================================================================
# Logparser 解析器
# ============================================================================

class LogparserParser(BaseParser):
    """Logparser 解析器，使用 INI 配置文件定义解析规则"""
    
    def __init__(self, name: str = "logparser", config: Optional[Dict[str, Any]] = None):
        """初始化 Logparser 解析器"""
        super().__init__(name, config)
        self.patterns = {}
        self.active_pattern = None
        
        config_file = self.config.get('config_file')
        if config_file:
            self.load_config_file(config_file)
        
        patterns_config = self.config.get('patterns', {})
        if patterns_config:
            self.load_patterns(patterns_config)
    
    def load_config_file(self, config_file: str):
        """加载 INI 格式的配置文件"""
        config = configparser.ConfigParser()
        config.read(config_file, encoding='utf-8')
        
        patterns = {}
        for section in config.sections():
            if section.startswith('pattern:'):
                pattern_name = section.replace('pattern:', '')
                pattern_config = {
                    'regex': config.get(section, 'regex', fallback=''),
                    'log_type': config.get(section, 'log_type', fallback='application'),
                    'description': config.get(section, 'description', fallback=''),
                }
                patterns[pattern_name] = pattern_config
        
        self.load_patterns(patterns)
        logger.info(f"Logparser 配置文件加载成功：{config_file}")
    
    def load_patterns(self, patterns: Dict[str, Dict[str, Any]]):
        """加载解析模式"""
        for name, pattern_config in patterns.items():
            try:
                compiled = re.compile(pattern_config['regex'])
                self.patterns[name] = {
                    'compiled': compiled,
                    'log_type': pattern_config.get('log_type', 'application'),
                    'description': pattern_config.get('description', ''),
                    'regex': pattern_config['regex'],
                }
                logger.debug(f"加载模式：{name}")
            except re.error as e:
                logger.error(f"模式 {name} 编译失败：{e}")
    
    def set_active_pattern(self, pattern_name: str):
        """设置当前使用的解析模式"""
        if pattern_name not in self.patterns:
            logger.error(f"模式不存在：{pattern_name}")
            return
        
        self.active_pattern = pattern_name
        logger.info(f"激活解析模式：{pattern_name}")
    
    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        """解析日志"""
        if self.active_pattern:
            return self._parse_with_pattern(raw_log, self.active_pattern)
        
        for pattern_name in self.patterns:
            result = self._parse_with_pattern(raw_log, pattern_name)
            if result:
                return result
        
        logger.debug(f"所有模式匹配失败：{raw_log[:100]}")
        return None
    
    def _parse_with_pattern(self, raw_log: str, pattern_name: str) -> Optional[Dict[str, Any]]:
        """使用指定模式解析日志"""
        pattern_info = self.patterns[pattern_name]
        compiled = pattern_info['compiled']
        
        try:
            match = compiled.match(raw_log.strip())
            if match:
                parsed_data = match.groupdict()
                
                extracted = FieldExtractor.extract_all_fields(parsed_data)
                
                if extracted.get('timestamp') and (extracted.get('username') or extracted.get('source_ip') or extracted.get('action')):
                    standard_log = StandardLogSchema.create_standard_log(
                        timestamp=extracted['timestamp'],
                        log_type=pattern_info['log_type'],
                        username=extracted['username'] or 'unknown',
                        action=extracted['action'] or 'UNKNOWN',
                        source_ip=extracted['source_ip'],
                        **{k: v for k, v in {
                            'destination_ip': extracted.get('destination_ip'),
                            'user_agent': parsed_data.get('user_agent'),
                            'uri': parsed_data.get('uri'),
                            'method': parsed_data.get('method'),
                            'status_code': parsed_data.get('status'),
                            'response_time': parsed_data.get('response_time'),
                            'detail': parsed_data.get('message') or parsed_data.get('detail'),
                            'event_type': parsed_data.get('event_type'),
                            'session_id': parsed_data.get('session_id'),
                        }.items() if v is not None}
                    )
                    standard_log['raw_log'] = raw_log
                    standard_log['parser'] = f"{self.name}:{pattern_name}"
                    return standard_log
                else:
                    parsed_data['raw_log'] = raw_log
                    parsed_data['parser'] = f"{self.name}:{pattern_name}"
                    parsed_data['parse_status'] = 'partial'
                    parsed_data['log_type'] = pattern_info['log_type']
                    return parsed_data
            else:
                return None
        except Exception as e:
            logger.error(f"解析失败 [{pattern_name}]: {e}")
            return None
    
    def parse_batch(self, raw_logs: List[str]) -> List[Dict[str, Any]]:
        """批量解析日志"""
        results = []
        for raw_log in raw_logs:
            parsed = self.parse(raw_log)
            if parsed:
                results.append(parsed)
        return results
    
    def add_pattern(self, name: str, regex: str, log_type: str = 'application', description: str = ''):
        """动态添加解析模式"""
        try:
            compiled = re.compile(regex)
            self.patterns[name] = {
                'compiled': compiled,
                'log_type': log_type,
                'description': description,
                'regex': regex,
            }
            logger.info(f"添加模式：{name}")
        except re.error as e:
            logger.error(f"添加模式失败 [{name}]: {e}")
            raise
    
    def get_patterns(self) -> List[str]:
        """获取所有可用的模式名称"""
        return list(self.patterns.keys())
    
    def get_pattern_info(self, pattern_name: str) -> Optional[Dict[str, Any]]:
        """获取模式详细信息"""
        if pattern_name not in self.patterns:
            return None
        
        info = self.patterns[pattern_name]
        return {
            'name': pattern_name,
            'regex': info['regex'],
            'log_type': info['log_type'],
            'description': info['description'],
        }


PREDEFINED_PATTERNS = {
    'vpn_login': {
        'regex': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<action>LOGIN|LOGOUT)\s+user=(?P<username>\w+)\s+ip=(?P<source_ip>[\d.]+)\s+status=(?P<status>\w+)',
        'log_type': 'vpn',
        'description': 'VPN 登录/登出日志',
    },
    'vpn_gateway': {
        'regex': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<vpn_gateway>\S+)\s+vpnd:\s+event=(?P<event_type>\S+)\s+user=(?P<username>\S+)\s+dept=(?P<dept>\S+)\s+src_ip=(?P<src_ip>[\d.]+)\s+src_geo=(?P<src_country>[^/]+)/(?P<src_city>\S+)\s+proto=(?P<protocol>\S+)\s+auth=(?P<auth_method>\S+)\s+client="(?P<client_software>[^"]+)"\s+session=(?P<session_id>\S+)\s+result=(?P<result>\S+)(?:\s+reason=(?P<fail_reason>[^ ]+))?(?:\s+duration=(?P<duration>\d+)s)?(?:\s+bytes_recv=(?P<bytes_recv>\d+))?(?:\s+bytes_sent=(?P<bytes_sent>\d+))?\s+risk_score=(?P<risk_score>\d+)\s+risk_tags="(?P<risk_tags>[^"]*)"',
        'log_type': 'vpn',
        'description': 'VPN 网关日志（含 5W1H 要素和行为基线）',
    },
    'oa_access': {
        'regex': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+user:(?P<username>\w+)\s+action:(?P<action>\w+)\s+module:(?P<module>\w+)\s+(?P<detail>.*)$',
        'log_type': 'oa',
        'description': 'OA 系统访问日志',
    },
    'api_request': {
        'regex': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<uri>/\S+)\s+user=(?P<username>\S+)\s+status=(?P<status>\d+)\s+response_time=(?P<response_time>[\d.]+)ms',
        'log_type': 'api',
        'description': 'API 请求日志',
    },
    'syslog_auth': {
        'regex': r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*(?:Accepted|Failed)\s+(?:password|publickey)\s+for\s+(?P<username>\w+)\s+from\s+(?P<source_ip>[\d.]+).*)',
        'log_type': 'system',
        'description': '系统认证日志',
    },
    'nginx_access': {
        'regex': r'^(?P<remote_addr>[\d.]+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<body_bytes_sent>\d+)\s+"(?P<http_referer>[^"]*)"\s+"(?P<http_user_agent>[^"]*)"',
        'log_type': 'network',
        'description': 'Nginx 访问日志',
    },
}


def create_default_logparser() -> LogparserParser:
    """创建默认的 Logparser 解析器，预加载常用模式"""
    parser = LogparserParser(name="logparser")
    parser.load_patterns(PREDEFINED_PATTERNS)
    return parser


# ============================================================================
# 解析方案选择器
# ============================================================================

def create_parser(log_type: str = 'auto', config: Optional[Dict[str, Any]] = None) -> BaseParser:
    """
    根据日志类型选择并创建解析器
    
    Args:
        log_type: 日志类型 ('json', 'vpn', 'nginx', 'api', 'syslog', 'auto' 等)
        config: 解析器配置
        
    Returns:
        对应的解析器实例
    """
    config = config or {}
    
    if log_type == 'json':
        return JSONParser(config=config)
    elif log_type in ['vpn', 'nginx', 'api', 'syslog', 'fortinet', 'oa', 'firewall', 'database', 'windows', 'linux_auth']:
        pattern_name = log_type if log_type in COMMON_PATTERNS else 'vpn_login'
        return RegexParser(
            name=f"regex_{log_type}",
            config={
                'pattern': COMMON_PATTERNS.get(pattern_name, COMMON_PATTERNS['vpn_login']),
                'log_type': log_type,
            }
        )
    elif log_type == 'auto':
        return create_default_logparser()
    else:
        return create_default_logparser()
"""
日志解析器集合

包含所有日志解析器实现：
- BaseParser: 解析器基类
- JSONParser: JSON 格式日志解析
- RegexParser: 正则表达式日志解析
- LogparserParser: INI 配置驱动的日志解析
- StandardLogSchema: 标准日志 Schema 定义
- FieldExtractor: 字段提取器
- 解析方案选择器：create_parser()

"""
import json
import re
import configparser
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime

from ..utils.logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# 解析器基类
# ============================================================================

class BaseParser(ABC):
    """日志解析器基类"""
    
    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        """
        初始化解析器
        
        Args:
            name: 解析器名称
            config: 配置字典
        """
        self.name = name
        self.config = config or {}
        
    @abstractmethod
    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        """
        解析单条日志
        
        Args:
            raw_log: 原始日志字符串
            
        Returns:
            解析后的字典，解析失败返回 None
        """
        pass
    
    def parse_batch(self, raw_logs: List[str]) -> List[Dict[str, Any]]:
        """
        批量解析日志
        
        Args:
            raw_logs: 原始日志列表
            
        Returns:
            解析后的字典列表
        """
        results = []
        for raw_log in raw_logs:
            parsed = self.parse(raw_log)
            if parsed:
                results.append(parsed)
        return results
    
    def validate_parsed(self, parsed_data: Dict[str, Any]) -> bool:
        """
        验证解析结果
        
        Args:
            parsed_data: 解析后的数据
            
        Returns:
            是否有效
        """
        return 'timestamp' in parsed_data
    
    def normalize_fields(self, log_data: Dict[str, Any], field_mappings: Dict[str, str]) -> Dict[str, Any]:
        """
        标准化字段名称
        
        Args:
            log_data: 原始解析数据
            field_mappings: 字段映射关系 {目标字段：源字段}
            
        Returns:
            标准化后的数据
        """
        result = {}
        for target_field, source_field in field_mappings.items():
            result[target_field] = log_data.get(source_field)
        return result


# ============================================================================
# 日志 Schema 定义
# ============================================================================

class LogSeverity(Enum):
    """日志严重程度"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogType(Enum):
    """日志类型"""
    VPN = "vpn"
    OA = "oa"
    API = "api"
    SYSTEM = "system"
    SECURITY = "security"
    APPLICATION = "application"
    NETWORK = "network"
    DATABASE = "database"


class ActionType(Enum):
    """常见行为类型"""
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    API_CALL = "API_CALL"
    FILE_ACCESS = "FILE_ACCESS"
    DATA_EXPORT = "DATA_EXPORT"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    NETWORK_ACCESS = "NETWORK_ACCESS"
    UNKNOWN = "UNKNOWN"


class StandardLogSchema:
    """
    标准日志 Schema 定义
    将所有日志统一转换为标准格式，支持用户行为分析和风险分析
    
    字段分类：
    1. 核心标识字段（必填）：唯一标识一条日志
    2. 5W1H行为分析字段：Who/What/When/Where/Why/How
    3. 用户行为基线字段：用于判断行为是否异常
    4. 风险分析字段：风险评分和标签
    5. 系统时间字段：日志生命周期时间戳
    6. 扩展字段：原始日志和解析信息
    """
    
    REQUIRED_FIELDS = [
        "timestamp",             # When: 日志生成时间
        "log_type",              # 日志类型
        "username",              # Who: 用户名
        "action",                # What: 行为动作
        "source_ip",             # Where: 来源IP
    ]
    
    OPTIONAL_FIELDS = [
        # === 5W1H 行为分析字段 ===
        "user_id",               # Who: 用户ID
        "dept",                  # Who: 部门
        "role",                  # Who: 角色
        "event_type",            # What: 事件类型
        "result",                # What: 结果
        "fail_reason",           # Why: 失败原因
        "destination_ip",        # Where: 目标IP
        "vpn_gateway",           # Where: 接入网关
        "src_country",           # Where: 来源国家
        "src_city",              # Where: 来源城市
        "protocol",              # How: 协议
        "auth_method",           # How: 认证方式
        "client_software",       # How: 客户端
        "session_id",            # How: 会话ID
        
        # === 用户行为基线字段 ===
        "is_off_hours",          # 是否非工作时间
        "is_unusual_ip",         # 是否异常IP
        "session_duration_sec",  # 会话时长
        "bytes_sent",            # 发送字节
        "bytes_recv",            # 接收字节
        
        # === 风险分析字段 ===
        "risk_score",            # 风险评分 0-100
        "risk_tags",             # 风险标签
        
        # === 通用扩展字段 ===
        "user_agent",
        "uri",
        "method",
        "status_code",
        "response_time",
        "detail",
        "severity_level",
        "device_info",
        "location",
        "request_id",
        
        # === 系统时间字段 ===
        "collected_at",          # 日志采集时间
        "parsed_at",             # 日志解析时间
        "indexed_at",            # 日志入库时间
        
        # === 原始数据 ===
        "raw_log",               # 原始日志
        "parser",                # 解析器
        "parse_status",          # 解析状态
    ]
    
    FIELD_TYPES = {
        "id": int,
        "timestamp": datetime,
        "log_type": str,
        "username": str,
        "user_id": str,
        "action": str,
        "event_type": str,
        "source_ip": str,
        "destination_ip": str,
        "user_agent": str,
        "uri": str,
        "method": str,
        "status_code": int,
        "response_time": float,
        "detail": str,
        "severity_level": str,
        "device_info": str,
        "location": str,
        "session_id": str,
        "request_id": str,
        "raw_log": str,
        "parser": str,
        "parse_status": str,
        "collected_at": datetime,
        "parsed_at": datetime,
        "indexed_at": datetime,
        # VPN专属字段
        "dept": str,
        "role": str,
        "result": str,
        "fail_reason": str,
        "vpn_gateway": str,
        "src_country": str,
        "src_city": str,
        "protocol": str,
        "auth_method": str,
        "client_software": str,
        "is_off_hours": bool,
        "is_unusual_ip": bool,
        "session_duration_sec": int,
        "bytes_sent": int,
        "bytes_recv": int,
        "risk_score": int,
        "risk_tags": str,
    }
    
    LOG_TYPE_MAPPINGS = {
        "vpn": ["vpn", "fortinet", "cisco_vpn", "anyconnect"],
        "oa": ["oa", "workflow", "审批", "办公"],
        "api": ["api", "rest", "graphql", "webservice"],
        "system": ["syslog", "windows_event", "auth", "secure"],
        "security": ["firewall", "ids", "ips", "waf", "antivirus"],
        "application": ["app", "service", "daemon"],
        "network": ["nginx", "apache", "proxy", "loadbalancer"],
        "database": ["mysql", "postgresql", "oracle", "mongodb"],
    }
    
    ACTION_MAPPINGS = {
        "LOGIN": ["login", "登入", "authenticate", "auth_success", "登录成功"],
        "LOGOUT": ["logout", "登出", "signout", "session_end"],
        "API_CALL": ["api_call", "request", "http_request", "rpc_call"],
        "FILE_ACCESS": ["file_access", "read", "write", "download", "upload"],
        "DATA_EXPORT": ["export", "download", "batch_download"],
        "CONFIG_CHANGE": ["config_change", "modify", "update_config"],
        "PERMISSION_CHANGE": ["permission_change", "grant", "revoke", "role_change"],
        "NETWORK_ACCESS": ["network_access", "connect", "disconnect"],
    }
    
    @classmethod
    def create_standard_log(
        cls,
        timestamp: datetime,
        log_type: str,
        username: str,
        action: str,
        source_ip: str,
        **kwargs
    ) -> Dict[str, Any]:
        """创建标准格式的日志字典"""
        standard_log = {
            "timestamp": timestamp,
            "log_type": log_type,
            "username": username,
            "action": action,
            "source_ip": source_ip,
        }
        
        for field in cls.OPTIONAL_FIELDS:
            if field in kwargs:
                standard_log[field] = kwargs[field]
        
        if "parse_status" not in standard_log:
            standard_log["parse_status"] = "success"
        
        if "parsed_at" not in standard_log:
            standard_log["parsed_at"] = datetime.now()
        
        return standard_log
    
    @classmethod
    def normalize_log_type(cls, raw_log_type: str) -> str:
        """标准化日志类型"""
        raw_log_type_lower = raw_log_type.lower()
        
        for standard_type, keywords in cls.LOG_TYPE_MAPPINGS.items():
            for keyword in keywords:
                if keyword in raw_log_type_lower:
                    return standard_type
        
        return "application"
    
    @classmethod
    def normalize_action(cls, raw_action: str) -> str:
        """标准化行为动作"""
        raw_action_lower = raw_action.lower()
        
        for standard_action, keywords in cls.ACTION_MAPPINGS.items():
            for keyword in keywords:
                if keyword in raw_action_lower:
                    return standard_action
        
        return "UNKNOWN"
    
    @classmethod
    def validate_log(cls, log_data: Dict[str, Any]) -> bool:
        """验证日志数据是否符合标准"""
        for field in cls.REQUIRED_FIELDS:
            if field not in log_data or log_data[field] is None:
                return False
        
        if not isinstance(log_data["timestamp"], datetime):
            return False
        
        import re as re_module
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if log_data.get("source_ip") and not re_module.match(ip_pattern, log_data["source_ip"]):
            return False
        
        return True
    
    @classmethod
    def to_json(cls, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """转换为 JSON 可序列化格式"""
        result = log_data.copy()
        
        for field, value in result.items():
            if isinstance(value, datetime):
                result[field] = value.isoformat()
            elif isinstance(value, Enum):
                result[field] = value.value
        
        return result


class FieldExtractor:
    """字段提取器"""
    
    @staticmethod
    def extract_username(parsed_data: Dict[str, Any]) -> Optional[str]:
        """提取用户名"""
        username_fields = ["username", "user", "account", "uid", "user_id", "login_user", "remote_user"]
        
        for field in username_fields:
            if field in parsed_data and parsed_data[field] and parsed_data[field] != '-':
                return str(parsed_data[field])
        
        # 从 message 中提取用户名（syslog 格式）
        if "message" in parsed_data:
            message = str(parsed_data["message"])
            # 匹配 "Accepted password for alice from" 或 "Failed password for bob from"
            match = re.search(r'(?:Accepted|Failed)\s+(?:password|publickey)\s+for\s+(\w+)\s+from', message)
            if match:
                return match.group(1)
        
        return None
    
    @staticmethod
    def extract_ip(parsed_data: Dict[str, Any], ip_type: str = "source") -> Optional[str]:
        """提取 IP 地址"""
        if ip_type == "source":
            ip_fields = ["source_ip", "src_ip", "ip", "remote_addr", "client_ip", "src"]
        else:
            ip_fields = ["destination_ip", "dst_ip", "dest_ip", "server_ip", "dst"]
        
        for field in ip_fields:
            if field in parsed_data and parsed_data[field]:
                return str(parsed_data[field])
        
        # 从 message 中提取 IP（syslog 格式）
        if ip_type == "source" and "message" in parsed_data:
            message = str(parsed_data["message"])
            match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
            if match:
                return match.group(1)
        
        return None
    
    @staticmethod
    def extract_timestamp(parsed_data: Dict[str, Any]) -> Optional[datetime]:
        """提取时间戳"""
        time_fields = ["timestamp", "time", "datetime", "date", "created_at", "@timestamp"]
        
        for field in time_fields:
            if field in parsed_data and parsed_data[field]:
                value = parsed_data[field]
                
                if isinstance(value, datetime):
                    return value
                
                if isinstance(value, str):
                    return FieldExtractor.parse_timestamp_string(value)
                
                if isinstance(value, (int, float)):
                    return datetime.fromtimestamp(value)
        
        return None
    
    @staticmethod
    def parse_timestamp_string(time_str: str) -> Optional[datetime]:
        """解析时间字符串"""
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%d/%b/%Y:%H:%M:%S %z",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(time_str, fmt)
            except ValueError:
                continue
        
        # 处理 syslog 格式（没有年份）： "May 15 12:11:24"
        try:
            current_year = datetime.now().year
            time_with_year = f"{current_year} {time_str}"
            return datetime.strptime(time_with_year, "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
    
    @staticmethod
    def extract_action(parsed_data: Dict[str, Any]) -> Optional[str]:
        """提取行为动作"""
        action_fields = ["action", "event", "event_type", "operation", "activity", "behavior", "verb"]
        
        for field in action_fields:
            if field in parsed_data and parsed_data[field]:
                return str(parsed_data[field])
        
        if "message" in parsed_data:
            message = str(parsed_data["message"]).upper()
            if "LOGIN" in message or "登入" in message or "ACCEPTED PASSWORD" in message or "ACCEPTED PUBLICKEY" in message:
                return "LOGIN"
            elif "LOGOUT" in message or "登出" in message:
                return "LOGOUT"
            elif "FAILED PASSWORD" in message or "FAILED PUBLICKEY" in message:
                return "LOGIN_FAILED"
        
        return None
    
    @staticmethod
    def extract_all_fields(parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """提取所有标准字段"""
        return {
            "username": FieldExtractor.extract_username(parsed_data),
            "source_ip": FieldExtractor.extract_ip(parsed_data, "source"),
            "destination_ip": FieldExtractor.extract_ip(parsed_data, "destination"),
            "timestamp": FieldExtractor.extract_timestamp(parsed_data),
            "action": FieldExtractor.extract_action(parsed_data),
        }


# ============================================================================
# JSON 解析器
# ============================================================================

class JSONParser(BaseParser):
    """JSON 日志解析器"""
    
    def __init__(self, name: str = "json", config: Optional[Dict[str, Any]] = None):
        """初始化 JSON 解析器"""
        super().__init__(name, config)
        self.field_mappings = self.config.get('field_mappings', {})
        
    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        """解析 JSON 格式日志"""
        try:
            parsed_data = json.loads(raw_log.strip())
            
            if self.field_mappings:
                parsed_data = self.normalize_fields(parsed_data, self.field_mappings)
            
            parsed_data['raw_log'] = raw_log
            parsed_data['parser'] = self.name
            parsed_data['parse_status'] = 'success'
            
            return parsed_data
        except json.JSONDecodeError as e:
            logger.debug(f"JSON 解析失败：{e}")
            return None
        except Exception as e:
            logger.error(f"解析 JSON 日志失败：{e}")
            return None
    
    def set_field_mappings(self, mappings: Dict[str, str]):
        """设置字段映射"""
        self.field_mappings = mappings
        logger.info(f"JSON 解析器 [{self.name}] 字段映射已更新")


# ============================================================================
# 正则解析器
# ============================================================================

class RegexParser(BaseParser):
    """正则表达式日志解析器"""
    
    def __init__(self, name: str = "regex", config: Optional[Dict[str, Any]] = None):
        """初始化正则解析器"""
        super().__init__(name, config)
        self.pattern = self.config.get('pattern')
        self.compiled_pattern = None
        self.log_type = self.config.get('log_type', 'application')
        
        if self.pattern:
            try:
                self.compiled_pattern = re.compile(self.pattern)
                logger.info(f"正则解析器 [{self.name}] 编译成功")
            except re.error as e:
                logger.error(f"正则表达式编译失败：{e}")
                raise
    
    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        """使用正则表达式解析日志"""
        if not self.compiled_pattern:
            logger.error("正则表达式未编译")
            return None
        
        try:
            match = self.compiled_pattern.match(raw_log.strip())
            if match:
                parsed_data = match.groupdict()
                
                extracted = FieldExtractor.extract_all_fields(parsed_data)
                
                if extracted.get('timestamp') and (extracted.get('username') or extracted.get('source_ip') or extracted.get('action')):
                    standard_log = StandardLogSchema.create_standard_log(
                        timestamp=extracted['timestamp'],
                        log_type=self.log_type,
                        username=extracted['username'] or 'unknown',
                        action=extracted['action'] or 'UNKNOWN',
                        source_ip=extracted.get('source_ip'),
                        **{k: v for k, v in {
                            # 5W1H 行为分析字段
                            'user_id': parsed_data.get('user_id'),
                            'dept': parsed_data.get('dept'),
                            'role': parsed_data.get('role'),
                            'event_type': parsed_data.get('event_type'),
                            'result': parsed_data.get('result'),
                            'fail_reason': parsed_data.get('fail_reason'),
                            'destination_ip': extracted.get('destination_ip'),
                            'vpn_gateway': parsed_data.get('vpn_gateway'),
                            'src_country': parsed_data.get('src_country'),
                            'src_city': parsed_data.get('src_city'),
                            'protocol': parsed_data.get('protocol'),
                            'auth_method': parsed_data.get('auth_method'),
                            'client_software': parsed_data.get('client_software'),
                            'user_agent': parsed_data.get('user_agent') or parsed_data.get('client_software'),
                            'uri': parsed_data.get('uri'),
                            'method': parsed_data.get('method'),
                            'status_code': parsed_data.get('status'),
                            'detail': parsed_data.get('message'),
                            'session_id': parsed_data.get('session_id'),
                            'severity_level': parsed_data.get('level'),
                            # 用户行为基线字段
                            'is_off_hours': parsed_data.get('is_off_hours'),
                            'is_unusual_ip': parsed_data.get('is_unusual_ip'),
                            'session_duration_sec': parsed_data.get('session_duration_sec'),
                            'bytes_sent': parsed_data.get('bytes_sent'),
                            'bytes_recv': parsed_data.get('bytes_recv'),
                            # 风险分析字段
                            'risk_score': parsed_data.get('risk_score'),
                            'risk_tags': parsed_data.get('risk_tags'),
                        }.items() if v is not None}
                    )
                    standard_log['raw_log'] = raw_log
                    standard_log['parser'] = self.name
                    return standard_log
                else:
                    parsed_data['raw_log'] = raw_log
                    parsed_data['parser'] = self.name
                    parsed_data['parse_status'] = 'partial'
                    return parsed_data
            else:
                logger.debug(f"日志不匹配正则模式：{raw_log[:100]}")
                return None
        except Exception as e:
            logger.error(f"解析日志失败：{e}")
            return None
    
    def update_pattern(self, new_pattern: str):
        """更新正则表达式"""
        try:
            self.compiled_pattern = re.compile(new_pattern)
            self.pattern = new_pattern
            logger.info(f"正则解析器 [{self.name}] 模式已更新")
        except re.error as e:
            logger.error(f"新正则表达式无效：{e}")
            raise


COMMON_PATTERNS = {
    'nginx_access': r'^(?P<remote_addr>[\d.]+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<body_bytes_sent>\d+)\s+"(?P<http_referer>[^"]*)"\s+"(?P<http_user_agent>[^"]*)"',
    'syslog': r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<program>\S+?)(\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$',
    'vpn_login': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<action>LOGIN|LOGOUT)\s+user=(?P<username>\w+)\s+ip=(?P<source_ip>[\d.]+)\s+status=(?P<status>\w+)',
    'vpn_gateway': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<vpn_gateway>\S+)\s+vpnd:\s+event=(?P<event_type>\S+)\s+user=(?P<username>\S+)\s+dept=(?P<dept>\S+)\s+src_ip=(?P<src_ip>[\d.]+)\s+src_geo=(?P<src_country>[^/]+)/(?P<src_city>\S+)\s+proto=(?P<protocol>\S+)\s+auth=(?P<auth_method>\S+)\s+client="(?P<client_software>[^"]+)"\s+session=(?P<session_id>\S+)\s+result=(?P<result>\S+)(?:\s+reason=(?P<fail_reason>[^ ]+))?(?:\s+duration=(?P<duration>\d+)s)?(?:\s+bytes_recv=(?P<bytes_recv>\d+))?(?:\s+bytes_sent=(?P<bytes_sent>\d+))?\s+risk_score=(?P<risk_score>\d+)\s+risk_tags="(?P<risk_tags>[^"]*)"',
    'fortinet_vpn': r'^date=(?P<timestamp>\d{4}-\d{2}-\d{2})\s+time=(?P<time>\d{2}:\d{2}:\d{2})\s+logid=\d+\s+type=event\s+subtype=vpn\s+level=notice\s+vd=root\s+user=(?P<username>\S+)\s+group=\S+\s+srcip=(?P<source_ip>[\d.]+)\s+action=(?P<action>ssl-login|ssl-logout)',
    'oa_system': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+user:(?P<username>\w+)\s+action:(?P<action>\w+)\s+module:(?P<module>\w+)\s+(?P<detail>.*)$',
    'api_call': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<uri>/\S+)\s+user=(?P<username>\S+)\s+status=(?P<status>\d+)\s+response_time=(?P<response_time>[\d.]+)ms',
    'windows_event': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<event_id>\d+)\s+(?P<level>\w+)\s+(?P<source>\S+)\s+(?P<message>.*)$',
    'database_query': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+user=(?P<username>\w+)\s+host=(?P<source_ip>[\d.]+)\s+query=(?P<query>.*)$',
    'firewall': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<action>ALLOW|DENY|DROP)\s+(?P<protocol>TCP|UDP|ICMP)\s+(?P<source_ip>[\d.]+):(?P<source_port>\d+)\s+->\s+(?P<destination_ip>[\d.]+):(?P<destination_port>\d+)',
    'linux_auth': r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*(?:Accepted|Failed)\s+(?:password|publickey)\s+for\s+(?P<username>\w+)\s+from\s+(?P<source_ip>[\d.]+).*)',
}


# ============================================================================
# Logparser 解析器
# ============================================================================

class LogparserParser(BaseParser):
    """Logparser 解析器，使用 INI 配置文件定义解析规则"""
    
    def __init__(self, name: str = "logparser", config: Optional[Dict[str, Any]] = None):
        """初始化 Logparser 解析器"""
        super().__init__(name, config)
        self.patterns = {}
        self.active_pattern = None
        
        config_file = self.config.get('config_file')
        if config_file:
            self.load_config_file(config_file)
        
        patterns_config = self.config.get('patterns', {})
        if patterns_config:
            self.load_patterns(patterns_config)
    
    def load_config_file(self, config_file: str):
        """加载 INI 格式的配置文件"""
        config = configparser.ConfigParser()
        config.read(config_file, encoding='utf-8')
        
        patterns = {}
        for section in config.sections():
            if section.startswith('pattern:'):
                pattern_name = section.replace('pattern:', '')
                pattern_config = {
                    'regex': config.get(section, 'regex', fallback=''),
                    'log_type': config.get(section, 'log_type', fallback='application'),
                    'description': config.get(section, 'description', fallback=''),
                }
                patterns[pattern_name] = pattern_config
        
        self.load_patterns(patterns)
        logger.info(f"Logparser 配置文件加载成功：{config_file}")
    
    def load_patterns(self, patterns: Dict[str, Dict[str, Any]]):
        """加载解析模式"""
        for name, pattern_config in patterns.items():
            try:
                compiled = re.compile(pattern_config['regex'])
                self.patterns[name] = {
                    'compiled': compiled,
                    'log_type': pattern_config.get('log_type', 'application'),
                    'description': pattern_config.get('description', ''),
                    'regex': pattern_config['regex'],
                }
                logger.debug(f"加载模式：{name}")
            except re.error as e:
                logger.error(f"模式 {name} 编译失败：{e}")
    
    def set_active_pattern(self, pattern_name: str):
        """设置当前使用的解析模式"""
        if pattern_name not in self.patterns:
            logger.error(f"模式不存在：{pattern_name}")
            return
        
        self.active_pattern = pattern_name
        logger.info(f"激活解析模式：{pattern_name}")
    
    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        """解析日志"""
        if self.active_pattern:
            return self._parse_with_pattern(raw_log, self.active_pattern)
        
        for pattern_name in self.patterns:
            result = self._parse_with_pattern(raw_log, pattern_name)
            if result:
                return result
        
        logger.debug(f"所有模式匹配失败：{raw_log[:100]}")
        return None
    
    def _parse_with_pattern(self, raw_log: str, pattern_name: str) -> Optional[Dict[str, Any]]:
        """使用指定模式解析日志"""
        pattern_info = self.patterns[pattern_name]
        compiled = pattern_info['compiled']
        
        try:
            match = compiled.match(raw_log.strip())
            if match:
                parsed_data = match.groupdict()
                
                extracted = FieldExtractor.extract_all_fields(parsed_data)
                
                if extracted.get('timestamp') and (extracted.get('username') or extracted.get('source_ip') or extracted.get('action')):
                    standard_log = StandardLogSchema.create_standard_log(
                        timestamp=extracted['timestamp'],
                        log_type=pattern_info['log_type'],
                        username=extracted['username'] or 'unknown',
                        action=extracted['action'] or 'UNKNOWN',
                        source_ip=extracted.get('source_ip'),
                        **{k: v for k, v in {
                            'destination_ip': extracted.get('destination_ip'),
                            'user_agent': parsed_data.get('user_agent'),
                            'uri': parsed_data.get('uri'),
                            'method': parsed_data.get('method'),
                            'status_code': parsed_data.get('status'),
                            'response_time': parsed_data.get('response_time'),
                            'detail': parsed_data.get('message') or parsed_data.get('detail'),
                            'event_type': parsed_data.get('event_type'),
                            'session_id': parsed_data.get('session_id'),
                        }.items() if v is not None}
                    )
                    standard_log['raw_log'] = raw_log
                    standard_log['parser'] = f"{self.name}:{pattern_name}"
                    return standard_log
                else:
                    parsed_data['raw_log'] = raw_log
                    parsed_data['parser'] = f"{self.name}:{pattern_name}"
                    parsed_data['parse_status'] = 'partial'
                    parsed_data['log_type'] = pattern_info['log_type']
                    return parsed_data
            else:
                return None
        except Exception as e:
            logger.error(f"解析失败 [{pattern_name}]: {e}")
            return None
    
    def parse_batch(self, raw_logs: List[str]) -> List[Dict[str, Any]]:
        """批量解析日志"""
        results = []
        for raw_log in raw_logs:
            parsed = self.parse(raw_log)
            if parsed:
                results.append(parsed)
        return results
    
    def add_pattern(self, name: str, regex: str, log_type: str = 'application', description: str = ''):
        """动态添加解析模式"""
        try:
            compiled = re.compile(regex)
            self.patterns[name] = {
                'compiled': compiled,
                'log_type': log_type,
                'description': description,
                'regex': regex,
            }
            logger.info(f"添加模式：{name}")
        except re.error as e:
            logger.error(f"添加模式失败 [{name}]: {e}")
            raise
    
    def get_patterns(self) -> List[str]:
        """获取所有可用的模式名称"""
        return list(self.patterns.keys())
    
    def get_pattern_info(self, pattern_name: str) -> Optional[Dict[str, Any]]:
        """获取模式详细信息"""
        if pattern_name not in self.patterns:
            return None
        
        info = self.patterns[pattern_name]
        return {
            'name': pattern_name,
            'regex': info['regex'],
            'log_type': info['log_type'],
            'description': info['description'],
        }


PREDEFINED_PATTERNS = {
    'vpn_gateway': {
        'regex': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<vpn_gateway>\S+)\s+vpnd:\s+event=(?P<event_type>\S+)\s+user=(?P<username>\S+)\s+dept=(?P<dept>\S+)\s+src_ip=(?P<src_ip>[\d.]+)\s+src_geo=(?P<src_country>[^/]+)/(?P<src_city>\S+)\s+proto=(?P<protocol>\S+)\s+auth=(?P<auth_method>\S+)\s+client="(?P<client_software>[^"]+)"\s+session=(?P<session_id>\S+)\s+result=(?P<result>\S+)(?:\s+reason=(?P<fail_reason>[^ ]+))?(?:\s+duration=(?P<duration>\d+)s)?(?:\s+bytes_recv=(?P<bytes_recv>\d+))?(?:\s+bytes_sent=(?P<bytes_sent>\d+))?\s+risk_score=(?P<risk_score>\d+)\s+risk_tags="(?P<risk_tags>[^"]*)"',
        'log_type': 'vpn',
        'description': 'VPN 网关日志（含 5W1H 要素和行为基线）',
    },
    'vpn_login': {
        'regex': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<action>LOGIN|LOGOUT)\s+user=(?P<username>\w+)\s+ip=(?P<source_ip>[\d.]+)\s+status=(?P<status>\w+)',
        'log_type': 'vpn',
        'description': 'VPN 登录/登出日志',
    },
    'oa_access': {
        'regex': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+user:(?P<username>\w+)\s+action:(?P<action>\w+)\s+module:(?P<module>\w+)\s+(?P<detail>.*)$',
        'log_type': 'oa',
        'description': 'OA 系统访问日志',
    },
    'api_request': {
        'regex': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<uri>/\S+)\s+user=(?P<username>\S+)\s+status=(?P<status>\d+)\s+response_time=(?P<response_time>[\d.]+)ms',
        'log_type': 'api',
        'description': 'API 请求日志',
    },
    'syslog_auth': {
        'regex': r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*(?:Accepted|Failed)\s+(?:password|publickey)\s+for\s+(?P<username>\w+)\s+from\s+(?P<source_ip>[\d.]+).*)',
        'log_type': 'system',
        'description': '系统认证日志',
    },
    'nginx_access': {
        'regex': r'^(?P<remote_addr>[\d.]+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<body_bytes_sent>\d+)\s+"(?P<http_referer>[^"]*)"\s+"(?P<http_user_agent>[^"]*)"',
        'log_type': 'network',
        'description': 'Nginx 访问日志',
    },
}


def create_default_logparser() -> LogparserParser:
    """创建默认的 Logparser 解析器，预加载常用模式"""
    parser = LogparserParser(name="logparser")
    parser.load_patterns(PREDEFINED_PATTERNS)
    return parser


# ============================================================================
# 解析方案选择器
# ============================================================================

def create_parser(log_type: str = 'auto', config: Optional[Dict[str, Any]] = None) -> BaseParser:
    """
    根据日志类型选择并创建解析器
    
    Args:
        log_type: 日志类型 ('json', 'vpn', 'nginx', 'api', 'syslog', 'auto' 等)
        config: 解析器配置
        
    Returns:
        对应的解析器实例
    """
    config = config or {}
    
    if log_type == 'json':
        return JSONParser(config=config)
    elif log_type in ['vpn', 'nginx', 'api', 'syslog', 'fortinet', 'oa', 'firewall', 'database', 'windows', 'linux_auth']:
        pattern_name = log_type if log_type in COMMON_PATTERNS else 'vpn_login'
        return RegexParser(
            name=f"regex_{log_type}",
            config={
                'pattern': COMMON_PATTERNS.get(pattern_name, COMMON_PATTERNS['vpn_login']),
                'log_type': log_type,
            }
        )
    elif log_type == 'auto':
        return create_default_logparser()
    else:
        return create_default_logparser()
