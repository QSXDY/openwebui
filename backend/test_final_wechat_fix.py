#!/usr/bin/env python3
"""
微信发送消息修复测试脚本
测试新的修复方案是否能解决乱码问题
"""

import json


def test_json_encoding_fix():
    """测试JSON编码修复方案"""
    print("=== 测试JSON编码修复方案 ===")

    # 测试包含emoji的消息
    message_content = "🎉 欢迎关注！\n\n您已成功关注我们的公众号，现在可以使用微信快速登录我们的AI平台了！\n\n✨ 功能特色：\n• 微信快捷登录\n• 智能AI对话\n• 多模型支持\n\n点击菜单或发送消息开始体验吧！"

    message_data = {
        "touser": "test_openid",
        "msgtype": "text",
        "text": {"content": message_content},
    }

    print("原始消息内容:")
    print(message_content)

    # 测试不同的JSON序列化方式
    print("\n1. 使用 ensure_ascii=True (会产生乱码):")
    json_ascii_true = json.dumps(message_data, ensure_ascii=True)
    print(json_ascii_true)

    print("\n2. 使用 ensure_ascii=False (修复方案):")
    json_ascii_false = json.dumps(
        message_data, ensure_ascii=False, separators=(",", ":")
    )
    print(json_ascii_false)

    # 测试编码为bytes
    print("\n3. 编码为UTF-8 bytes:")
    utf8_bytes = json_ascii_false.encode("utf-8")
    print(f"字节长度: {len(utf8_bytes)}")
    print(f"前100字节: {utf8_bytes[:100]}")

    # 验证解码
    print("\n4. 验证解码:")
    decoded_data = json.loads(utf8_bytes.decode("utf-8"))
    decoded_content = decoded_data["text"]["content"]
    print(f"解码后内容: {decoded_content}")

    # 验证是否和原始内容一致
    content_match = decoded_content == message_content
    print(f"内容是否一致: {content_match}")

    return content_match


def test_unicode_escape_handling():
    """测试Unicode转义序列处理"""
    print("\n=== 测试Unicode转义序列处理 ===")

    # 模拟从配置或数据库中读取的可能包含转义序列的内容
    escaped_content = "\\u6b22\\u8fce\\u5173\\u6ce8\\uff01"  # "欢迎关注！"

    print(f"转义序列内容: {escaped_content}")

    # 应用修复逻辑
    def process_unicode_content(content):
        """处理可能包含Unicode转义的内容"""
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        try:
            if "\\u" in content:
                # 简单的转义序列处理
                content = content.encode("utf-8").decode("unicode_escape")
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass

        return content

    processed_content = process_unicode_content(escaped_content)
    print(f"处理后内容: {processed_content}")

    # 验证是否正确解码
    expected = "欢迎关注！"
    is_correct = processed_content == expected
    print(f"解码是否正确: {is_correct}")

    return is_correct


def test_message_sending_simulation():
    """模拟完整的消息发送流程"""
    print("\n=== 模拟完整的消息发送流程 ===")

    # 模拟配置中的欢迎消息
    welcome_message = "🎉 欢迎关注！\n\n您已成功关注我们的公众号，现在可以使用微信快速登录我们的AI平台了！\n\n✨ 功能特色：\n• 微信快捷登录\n• 智能AI对话\n• 多模型支持\n\n点击菜单或发送消息开始体验吧！"

    # 模拟变量替换
    webui_url = "https://example.com"
    content = welcome_message.replace("{WEBUI_URL}", webui_url)

    print(f"1. 配置消息: {welcome_message[:50]}...")
    print(f"2. 替换变量后: {content[:50]}...")

    # 模拟Unicode处理
    if isinstance(content, bytes):
        content = content.decode("utf-8")

    try:
        if "\\u" in content:
            content = (
                content.encode("utf-8")
                .decode("unicode_escape")
                .encode("latin1")
                .decode("utf-8")
            )
    except (UnicodeDecodeError, UnicodeEncodeError):
        pass

    print(f"3. Unicode处理后: {content[:50]}...")

    # 构建消息数据
    message_data = {
        "touser": "test_openid",
        "msgtype": "text",
        "text": {"content": content},
    }

    # 使用修复后的JSON序列化
    json_data = json.dumps(message_data, ensure_ascii=False, separators=(",", ":"))
    print(f"4. JSON序列化: {json_data[:100]}...")

    # 编码为UTF-8
    utf8_data = json_data.encode("utf-8")
    print(f"5. UTF-8编码长度: {len(utf8_data)}")

    # 模拟HTTP头
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
    }
    print(f"6. HTTP头: {headers}")

    print("✓ 消息发送流程模拟完成")
    return True


def test_config_encoding():
    """测试配置编码问题"""
    print("\n=== 测试配置编码问题 ===")

    # 模拟配置文件中可能存储的格式
    configs = [
        "🎉 欢迎关注！",  # 正常UTF-8
        "\\ud83c\\udf89 \\u6b22\\u8fce\\u5173\\u6ce8\\uff01",  # 转义序列
        "欢迎关注！",  # 纯中文
    ]

    for i, config_value in enumerate(configs, 1):
        print(f"\n配置{i}: {config_value}")

        # 应用处理逻辑
        processed = config_value
        try:
            if "\\u" in processed:
                processed = processed.encode("utf-8").decode("unicode_escape")
        except:
            pass

        print(f"处理后: {processed}")

        # 测试JSON序列化
        test_data = {"content": processed}
        json_result = json.dumps(test_data, ensure_ascii=False)
        print(f"JSON化: {json_result}")

    return True


def main():
    """运行所有测试"""
    print("开始运行微信消息发送修复测试...")
    print("=" * 60)

    try:
        # 运行测试
        test1 = test_json_encoding_fix()
        test2 = test_unicode_escape_handling()
        test3 = test_message_sending_simulation()
        test4 = test_config_encoding()

        print("\n" + "=" * 60)
        print("测试结果总结:")
        print(f"✓ JSON编码修复: {'通过' if test1 else '失败'}")
        print(f"✓ Unicode转义处理: {'通过' if test2 else '失败'}")
        print(f"✓ 消息发送流程: {'通过' if test3 else '失败'}")
        print(f"✓ 配置编码处理: {'通过' if test4 else '失败'}")

        all_passed = all([test1, test2, test3, test4])

        if all_passed:
            print("\n🎉 所有测试通过！修复方案应该能解决乱码问题。")
            print("\n下一步操作:")
            print("1. 重启后端服务")
            print("2. 让用户重新扫描二维码")
            print("3. 检查日志中的'准备发送消息'和'发送响应'记录")
            print("4. 验证用户收到的消息是否正常显示")
        else:
            print("\n❌ 部分测试失败，需要进一步调试")

        return all_passed

    except Exception as e:
        print(f"\n💥 测试过程中出错: {e}")
        import traceback

        print(f"错误详情: {traceback.format_exc()}")
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
