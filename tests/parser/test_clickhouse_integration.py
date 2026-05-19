#!/usr/bin/env python3
"""
Parser 模块与 ClickHouse 集成测试脚本
演示如何将解析后的日志数据存入 ClickHouse

使用方式:
    python tests/parser/test_clickhouse_integration.py
"""
import sys
from pathlib import Path
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.parsers import (
    LogProcessor,
    ClickHouseDataSink,
    JSONParser,
    RegexParser,
    COMMON_PATTERNS,
    StandardLogSchema,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)

# ClickHouse 配置（根据你的实际配置修改）
CLICKHOUSE_CONFIG = {
    'host': 'localhost',
    'port': 8123,
    'username': 'default',
    'password': '',
    'database': 'log_analysis',
}

# 获取当前日期用于测试数据
NOW = datetime.now()
CURRENT_DATE = NOW.strftime("%Y-%m-%d")
CURRENT_DATE_NGINX = NOW.strftime("%d/%b/%Y:%H:%M:%S +0000")
CURRENT_ISO_DATE = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")

# 测试日志样本（使用当前日期避免 TTL 过期）
TEST_LOGS = [
    # JSON 格式日志
    f'{{"timestamp": "{CURRENT_DATE} 10:30:00", "username": "admin", "action": "LOGIN", "source_ip": "192.168.1.100", "log_type": "vpn", "status": "SUCCESS"}}',
    
    # Nginx 访问日志
    f'192.168.1.50 - admin [{CURRENT_DATE_NGINX}] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    
    # VPN 登录日志
    f'{CURRENT_DATE} 10:32:00 LOGIN user=john ip=10.0.0.50 status=SUCCESS',
    
    # 系统日志
    f'{NOW.strftime("%b")} {NOW.day} {NOW.strftime("%H:%M:%S")} server01 sshd[12345]: Accepted password for alice from 172.16.0.100 port 22 ssh2',
    
    # API 调用日志
    f'{CURRENT_ISO_DATE} POST /api/v1/data user=bob status=201 response_time=125.5ms',
]


def test_clickhouse_sink():
    """测试 ClickHouse 数据输出"""
    print("=" * 60)
    print("测试 1: ClickHouseDataSink 直接插入")
    print("=" * 60)
    
    # 创建数据输出实例
    sink = ClickHouseDataSink(config=CLICKHOUSE_CONFIG)
    
    try:
        # 连接 ClickHouse
        if not sink.connect():
            print("❌ ClickHouse 连接失败，请检查配置和服务状态")
            return False
        
        print("✅ ClickHouse 连接成功")
        
        # 准备测试数据
        test_data = []
        for i, log in enumerate(TEST_LOGS):
            test_data.append({
                'timestamp': datetime.now(),
                'log_type': 'test',
                'source': 'integration_test',
                'username': f'test_user_{i}',
                'action': 'TEST_ACTION',
                'source_ip': '127.0.0.1',
                'detail': f'Test log entry {i}',
                'collected_at': datetime.now(),
                'parsed_at': datetime.now(),
            })
        
        # 插入数据
        if sink.insert(test_data, table='logs_structured'):
            print(f"✅ 成功插入 {len(test_data)} 条测试数据")
        else:
            print("❌ 数据插入失败")
            return False
        
        # 关闭连接
        sink.close()
        print("✅ 连接已关闭")
        
        return True
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        return False


def test_log_processor_with_clickhouse():
    """测试 LogProcessor 与 ClickHouse 集成"""
    print("\n" + "=" * 60)
    print("测试 2: LogProcessor + ClickHouseDataSink 集成")
    print("=" * 60)
    
    # 创建 ClickHouse 数据输出
    sink = ClickHouseDataSink(config=CLICKHOUSE_CONFIG)
    
    if not sink.connect():
        print("❌ ClickHouse 连接失败，请检查配置和服务状态")
        return False
    
    print("✅ ClickHouse 连接成功")
    
    # 创建日志处理器，传入数据输出
    processor = LogProcessor(data_sink=sink)
    
    try:
        # 解析测试日志
        parsed_logs = []
        for i, raw_log in enumerate(TEST_LOGS):
            print(f"\n解析日志 {i+1}: {raw_log[:80]}...")
            parsed = processor.parse_log(raw_log)
            if parsed:
                cleaned = processor.clean_log(parsed)
                if cleaned:
                    parsed_logs.append(cleaned)
                    print(f"  ✅ 解析成功: {parsed.get('parser', 'unknown')}")
                else:
                    print(f"  ⚠️  清洗后被过滤")
            else:
                print(f"  ❌ 解析失败")
        
        print(f"\n共解析 {len(parsed_logs)}/{len(TEST_LOGS)} 条日志")
        
        # 输出到 ClickHouse
        if parsed_logs:
            processor.output_data(parsed_logs, table='logs_structured')
            print(f"✅ 成功输出 {len(parsed_logs)} 条日志到 ClickHouse")
        
        # 关闭连接
        sink.close()
        print("✅ 连接已关闭")
        
        return True
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_standard_schema_conversion():
    """测试标准 Schema 转换"""
    print("\n" + "=" * 60)
    print("测试 3: StandardLogSchema 转换")
    print("=" * 60)
    
    # 创建标准日志
    standard_log = StandardLogSchema.create_standard_log(
        timestamp=datetime.now(),
        log_type='vpn',
        username='test_user',
        action='LOGIN',
        source_ip='192.168.1.100',
        user_agent='Mozilla/5.0',
        uri='/api/login',
        method='POST',
        status_code=200,
        response_time=150.5,
        detail='Test login',
    )
    
    print(f"标准日志 Schema:")
    for key, value in standard_log.items():
        print(f"  {key}: {value}")
    
    # 验证
    if StandardLogSchema.validate_log(standard_log):
        print("\n✅ 日志验证通过")
        return True
    else:
        print("\n❌ 日志验证失败")
        return False


def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("Parser 模块与 ClickHouse 集成测试")
    print("=" * 60 + "\n")
    
    results = []
    
    # 测试 1: 标准 Schema 转换
    results.append(('StandardLogSchema 转换', test_standard_schema_conversion()))
    
    # 测试 2: ClickHouseDataSink 直接插入
    results.append(('ClickHouseDataSink 直接插入', test_clickhouse_sink()))
    
    # 测试 3: LogProcessor 集成
    results.append(('LogProcessor + ClickHouse 集成', test_log_processor_with_clickhouse()))
    
    # 输出测试结果
    print("\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)
    
    for name, passed in results:
        status = "✅ 通过" if passed else "❌ 失败"
        print(f"{status} - {name}")
    
    all_passed = all(r[1] for r in results)
    print("\n" + "=" * 60)
    if all_passed:
        print("✅ 所有测试通过！")
    else:
        print("❌ 部分测试失败，请检查日志和配置")
    print("=" * 60 + "\n")
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())
