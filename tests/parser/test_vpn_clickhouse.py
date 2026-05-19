#!/usr/bin/env python3
"""
测试 VPN 日志解析并写入 ClickHouse
验证新字段是否正确解析和入库
"""
import sys
from pathlib import Path
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.parsers import (
    LogProcessor,
    ClickHouseDataSink,
    RegexParser,
    PREDEFINED_PATTERNS,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)

CLICKHOUSE_CONFIG = {
    'host': 'localhost',
    'port': 8123,
    'username': 'default',
    'password': '',
    'database': 'log_analysis',
}

def test_vpn_logs_parsing():
    """测试 VPN 日志解析"""
    print("\n" + "=" * 60)
    print("测试: VPN 日志解析与 ClickHouse 入库")
    print("=" * 60)
    
    # 创建 VPN 日志解析器
    vpn_config = PREDEFINED_PATTERNS['vpn_gateway']
    parser = RegexParser(name='vpn_gateway', config={
        'pattern': vpn_config['regex'],
        'log_type': vpn_config['log_type'],
    })
    
    # 读取测试日志
    log_file = Path(__file__).parent.parent.parent / '.trae' / 'dingding' / 'vpn_logs.log'
    with open(log_file, 'r') as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
    
    print(f"\n读取到 {len(lines)} 条日志")
    
    # 解析日志
    parsed_logs = []
    for line in lines:
        result = parser.parse(line)
        if result:
            parsed_logs.append(result)
    
    print(f"解析成功: {len(parsed_logs)}/{len(lines)}")
    
    if parsed_logs:
        print("\n=== 前3条解析结果示例 ===")
        for i, log in enumerate(parsed_logs[:3]):
            print(f"\n日志 {i+1}:")
            for key in ['timestamp', 'username', 'dept', 'role', 'action', 'event_type', 
                       'result', 'source_ip', 'src_country', 'src_city', 'vpn_gateway',
                       'protocol', 'auth_method', 'client_software', 'session_id',
                       'is_off_hours', 'is_unusual_ip', 'session_duration_sec', 
                       'bytes_sent', 'bytes_recv', 'risk_score', 'risk_tags']:
                print(f"  {key}: {log.get(key, 'N/A')}")
    
    return parsed_logs


def test_vpn_logs_to_clickhouse(parsed_logs):
    """测试将 VPN 日志写入 ClickHouse"""
    print("\n" + "=" * 60)
    print("测试: VPN 日志写入 ClickHouse")
    print("=" * 60)
    
    if not parsed_logs:
        print("❌ 没有解析后的日志")
        return False
    
    try:
        # 创建 ClickHouse 数据输出
        sink = ClickHouseDataSink(config=CLICKHOUSE_CONFIG)
        
        if not sink.connect():
            print("❌ ClickHouse 连接失败")
            return False
        
        print("✅ ClickHouse 连接成功")
        
        # 插入数据
        success = sink.insert(parsed_logs)
        if success:
            print(f"✅ 成功插入 {len(parsed_logs)} 条 VPN 日志")
        else:
            print("❌ 插入失败")
            return False
        
        sink.close()
        print("✅ 连接已关闭")
        
        return True
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("VPN 日志解析与 ClickHouse 入库测试")
    print("=" * 60 + "\n")
    
    # 测试 1: 解析 VPN 日志
    parsed_logs = test_vpn_logs_parsing()
    
    # 测试 2: 写入 ClickHouse
    insert_success = test_vpn_logs_to_clickhouse(parsed_logs)
    
    print("\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)
    print(f"✅ 解析成功: {len(parsed_logs)} 条")
    print(f"{'✅' if insert_success else '❌'} 入库: {'成功' if insert_success else '失败'}")
    print("=" * 60 + "\n")
    
    return 0 if insert_success else 1


if __name__ == '__main__':
    sys.exit(main())
