#!/usr/bin/env python3
"""
测试Unicode编码修复脚本
"""

def test_unicode_decoding():
    """测试Unicode解码处理"""
    print("=== 测试Unicode解码处理 ===")
    
    # 模拟用户收到的乱码内容
    unicode_escaped = "\\ud83c\\udf89 \\u6b22\\u8fce\\u5173\\u6ce8\\uff01\\n\\n\\u60a8\\u5df2\\u6210\\u529f\\u5173\\u6ce8\\u6211\\u4eec\\u7684\\u516c\\u4f17\\u53f7\\uff0c\\u73b0\\u5728\\u53ef\\u4ee5\\u4f7f\\u7528\\u5fae\\u4fe1\\u5feb\\u901f\\u767b\\u5f55\\u6211\\u4eec\\u7684AI\\u5e73\\u53f0\\u4e86\\uff01\\n\\n\\u2728 \\u529f\\u80fd\\u7279\\u8272\\uff1a\\n\\u2022 \\u5fae\\u4fe1\\u5feb\\u6377\\u767b\\u5f55\\n\\u2022 \\u667a\\u80fdAI\\u5bf9\\u8bdd\\n\\u2022 \\u591a\\u6a21\\u578b\\u652f\\u6301\\n\\n\\u70b9\\u51fb\\u83dc\\u5355\\u6216\\u53d1\\u9001\\u6d88\\u606f\\u5f00\\u59cb\\u4f53\\u9a8c\\u5427\\uff01"
    
    print(f"原始Unicode转义字符串:")
    print(unicode_escaped)
    
    # 测试解码方法
    try:
        # 方法1：直接unicode_escape解码
        decoded1 = unicode_escaped.encode('utf-8').decode('unicode_escape')
        print(f"\n方法1解码结果:")
        print(decoded1)
    except Exception as e:
        print(f"方法1解码失败: {e}")
    
    try:
        # 方法2：处理双重编码（推荐）
        decoded2 = unicode_escaped.encode('utf-8').decode('unicode_escape').encode('latin1').decode('utf-8')
        print(f"\n方法2解码结果:")
        print(decoded2)
    except Exception as e:
        print(f"方法2解码失败: {e}")
    
    # 正确的消息内容应该是
    correct_message = "🎉 欢迎关注！\n\n您已成功关注我们的公众号，现在可以使用微信快速登录我们的AI平台了！\n\n✨ 功能特色：\n• 微信快捷登录\n• 智能AI对话\n• 多模型支持\n\n点击菜单或发送消息开始体验吧！"
    
    print(f"\n正确的消息内容应该是:")
    print(correct_message)
    
    return decoded2 if 'decoded2' in locals() else decoded1


def test_message_processing():
    """测试消息处理逻辑"""
    print("\n=== 测试消息处理逻辑 ===")
    
    # 模拟配置中的消息（可能包含Unicode转义）
    config_message = "🎉 欢迎关注！\n\n您已成功关注我们的公众号，现在可以使用微信快速登录我们的AI平台了！\n\n✨ 功能特色：\n• 微信快捷登录\n• 智能AI对话\n• 多模型支持\n\n点击菜单或发送消息开始体验吧！"
    
    print(f"配置中的消息:")
    print(config_message)
    
    # 应用修复后的处理逻辑
    def process_message_content(content):
        """处理消息内容的编码"""
        # 确保内容是正确的UTF-8字符串
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        
        # 处理可能的Unicode转义序列
        try:
            # 如果内容包含Unicode转义序列，进行解码
            if '\\u' in content:
                content = content.encode('utf-8').decode('unicode_escape').encode('latin1').decode('utf-8')
        except (UnicodeDecodeError, UnicodeEncodeError):
            # 如果解码失败，保持原内容
            pass
        
        return content
    
    processed_message = process_message_content(config_message)
    print(f"\n处理后的消息:")
    print(processed_message)
    
    # 测试变量替换
    webui_url = "https://example.com"
    final_message = processed_message.replace("{WEBUI_URL}", webui_url)
    print(f"\n替换变量后的消息:")
    print(final_message)
    
    return final_message


def test_json_encoding():
    """测试JSON编码"""
    print("\n=== 测试JSON编码 ===")
    
    import json
    
    message_content = "🎉 欢迎关注！\n\n您已成功关注我们的公众号！"
    
    # 测试JSON编码
    message_data = {
        "touser": "test_openid",
        "msgtype": "text",
        "text": {"content": message_content},
    }
    
    # 不同的JSON编码方式
    json_str1 = json.dumps(message_data, ensure_ascii=False)
    json_str2 = json.dumps(message_data, ensure_ascii=True)
    
    print(f"ensure_ascii=False:")
    print(json_str1)
    
    print(f"\nensure_ascii=True:")
    print(json_str2)
    
    # 解码测试
    decoded_data1 = json.loads(json_str1)
    decoded_data2 = json.loads(json_str2)
    
    print(f"\n解码后内容1: {decoded_data1['text']['content']}")
    print(f"解码后内容2: {decoded_data2['text']['content']}")
    
    return message_data


def main():
    """运行所有测试"""
    print("开始运行Unicode编码修复测试...")
    print("=" * 50)
    
    try:
        # 测试Unicode解码
        decoded_message = test_unicode_decoding()
        
        # 测试消息处理
        processed_message = test_message_processing()
        
        # 测试JSON编码
        json_data = test_json_encoding()
        
        print("\n" + "=" * 50)
        print("所有测试完成！")
        
        print("\n解决方案总结:")
        print("1. 在send_text_message方法中添加Unicode转义序列处理")
        print("2. 确保JSON发送时使用正确的UTF-8编码")
        print("3. 添加详细的日志记录便于调试")
        
        print("\n建议:")
        print("1. 重启服务应用修复")
        print("2. 检查日志中的'准备发送消息'记录，确认内容正确")
        print("3. 测试发送消息是否正常显示")
        
    except Exception as e:
        print(f"测试出错: {e}")
        import traceback
        print(f"错误详情: {traceback.format_exc()}")
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 