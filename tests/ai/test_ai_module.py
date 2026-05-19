"""
AI 模块测试脚本
用于验证 AI API 调用是否正常工作
"""
import sys
import os

# 添加 src 目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from dotenv import load_dotenv

# 加载 .env 文件
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

# 使用绝对导入
from ai.analyzer import AIAnalyzer
from ai.client import AIClient
from ai.threat_classifier import ThreatClassifier


def get_current_platform():
    """获取当前配置的 AI 平台"""
    platform = os.getenv("AI_PLATFORM", "").lower()
    api_keys = {
        "kimi": os.getenv("MOONSHOT_API_KEY"),
        "siliconflow": os.getenv("SILICONFLOW_API_KEY"),
        "dashscope": os.getenv("DASHSCOPE_API_KEY"),
        "openai": os.getenv("OPENAI_API_KEY"),
        "zhipu": os.getenv("ZHIPU_API_KEY"),
    }
    
    if platform in api_keys and api_keys[platform]:
        return platform, api_keys[platform]
    
    for p, key in api_keys.items():
        if key:
            return p, key
    
    return None, None


def test_ai_client():
    """测试 AI 客户端"""
    print("\n" + "=" * 50)
    print("测试 AI 客户端")
    print("=" * 50)

    platform, api_key = get_current_platform()
    if not api_key:
        print("错误：未找到 API Key，请检查 .env 文件")
        return False

    print(f"使用平台: {platform}")

    try:
        client = AIClient(api_key=api_key, platform=platform)
        print(f"客户端创建成功: {client.model}")

        response = client.chat(
            messages=[
                {"role": "user", "content": "请回复 '测试成功'"}
            ],
            temperature=0.1,
        )
        print(f"API 响应: {response}")
        return True
    except Exception as e:
        print(f"API 调用失败: {e}")
        return False


def test_threat_classifier():
    """测试威胁分类器"""
    print("\n" + "=" * 50)
    print("测试威胁分类器")
    print("=" * 50)

    classifier = ThreatClassifier()

    test_cases = [
        {"description": "用户登录失败，密码错误", "expected": "BRUTE_FORCE"},
        {"description": "账号在异地登录", "expected": "CREDENTIAL_STUFFING"},
        {"description": "非工作时间访问敏感数据", "expected": "UNUSUAL_ACCESS"},
        {"description": "尝试执行 sudo 命令", "expected": "PRIVILEGE_ESCALATION"},
        {"description": "大量下载敏感文件", "expected": "DATA_EXFILTRATION"},
    ]

    all_passed = True
    for case in test_cases:
        result = classifier.classify(case)
        status = "✓" if result == case["expected"] else "✗"
        print(f"{status} 输入: {case['description']}")
        print(f"  期望: {case['expected']}, 实际: {result}")
        if result != case["expected"]:
            all_passed = False

    return all_passed


def test_analyzer():
    """测试 AI 分析器"""
    print("\n" + "=" * 50)
    print("测试 AI 分析器")
    print("=" * 50)

    platform, api_key = get_current_platform()
    if not api_key:
        print("错误：未找到 API Key，请检查 .env 文件")
        return False

    try:
        analyzer = AIAnalyzer(api_key=api_key, platform=platform)

        result = analyzer.analyze_anomaly(
            username="test_user",
            anomaly_description="用户短时间内多次登录失败",
            log_context="2026-05-13 10:00:00 login failed\n2026-05-13 10:00:05 login failed\n2026-05-13 10:00:10 login failed",
        )

        print(f"分析结果:")
        print(f"  威胁类型: {result['threat_type']}")
        print(f"  风险等级: {result['risk_level']}")
        print(f"  描述: {result['description'][:100]}..." if len(result['description']) > 100 else f"  描述: {result['description']}")
        print(f"  建议: {result['suggestion'][:100]}..." if len(result['suggestion']) > 100 else f"  建议: {result['suggestion']}")

        return True
    except Exception as e:
        print(f"分析失败: {e}")
        return False


def main():
    """主测试函数"""
    print("\n" + "=" * 60)
    print("AI 模块测试")
    print("=" * 60)

    results = {}

    results["ai_client"] = test_ai_client()
    results["threat_classifier"] = test_threat_classifier()
    results["analyzer"] = test_analyzer()

    print("\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)
    for test_name, passed in results.items():
        status = "通过" if passed else "失败"
        print(f"  {test_name}: {status}")

    all_passed = all(results.values())
    print("\n" + ("全部测试通过!" if all_passed else "部分测试失败，请检查配置"))

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
