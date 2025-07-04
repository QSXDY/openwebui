import re
import uuid
import time
import datetime
import logging
import random
import json
import socket
from decimal import Decimal
import hashlib
import urllib.parse
import qrcode
from io import BytesIO
import base64
import struct
import xml.etree.ElementTree as ET

try:
    from Crypto.Cipher import AES

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from aiohttp import ClientSession

from open_webui.models.auths import (
    AddUserForm,
    ApiKey,
    Auths,
    UserBindings,
    Token,
    LdapForm,
    SigninForm,
    SigninResponse,
    SignupForm,
    UpdatePasswordForm,
    UpdateProfileForm,
    UserResponse,
)
from open_webui.models.credits import Credits
from open_webui.models.users import Users, UserModel
from open_webui.utils.auth import get_license_data
from open_webui.constants import ERROR_MESSAGES, WEBHOOK_MESSAGES
from open_webui.env import (
    WEBUI_AUTH,
    WEBUI_AUTH_TRUSTED_EMAIL_HEADER,
    WEBUI_AUTH_TRUSTED_NAME_HEADER,
    WEBUI_AUTH_COOKIE_SAME_SITE,
    WEBUI_AUTH_COOKIE_SECURE,
    WEBUI_AUTH_SIGNOUT_REDIRECT_URL,
    SRC_LOG_LEVELS,
)
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from open_webui.config import (
    OPENID_PROVIDER_URL,
    ENABLE_OAUTH_SIGNUP,
    ENABLE_LDAP,
)
from pydantic import BaseModel, Field

from open_webui.utils.misc import parse_duration, validate_email_format
from open_webui.utils.auth import (
    decode_token,
    create_api_key,
    create_token,
    get_admin_user,
    get_verified_user,
    get_current_user,
    get_password_hash,
    get_http_authorization_cred,
    send_verify_email,
    verify_email_by_code,
)
from open_webui.utils.webhook import post_webhook
from open_webui.utils.access_control import get_permissions

from typing import Optional, List, Literal

from ssl import CERT_REQUIRED, PROTOCOL_TLS

# 阿里云短信服务相关导入
try:
    from alibabacloud_dysmsapi20170525.client import Client as DysmsapiClient
    from alibabacloud_tea_openapi import models as open_api_models
    from alibabacloud_dysmsapi20170525 import models as dysmsapi_models
    from alibabacloud_tea_util import models as util_models

    SMS_AVAILABLE = True
except ImportError:
    SMS_AVAILABLE = False
    log.warning("阿里云短信SDK未安装，短信功能将不可用")

if ENABLE_LDAP.value:
    from ldap3 import Server, Connection, NONE, Tls
    from ldap3.utils.conv import escape_filter_chars

router = APIRouter()

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MAIN"])

if not CRYPTO_AVAILABLE:
    log.warning(
        "PyCryptodome未安装，微信消息解密功能将不可用。请运行 'pip install pycryptodome'"
    )


class PKCS7Encoder:
    """提供PKCS7补位/去补位功能"""

    block_size = 32

    @staticmethod
    def decode(decrypted):
        pad = decrypted[-1]
        if pad < 1 or pad > PKCS7Encoder.block_size:
            pad = 0
        return decrypted[:-pad]


# 短信验证码存储（生产环境建议使用Redis）
sms_verification_codes = {}

# 临时存储已验证手机号的注册信息（等待绑定微信）
pending_phone_registrations = {}


# 短信服务配置类
class SMSConfig:
    def __init__(self, request):
        self.ACCESS_KEY_ID = request.app.state.config.SMS_ACCESS_KEY_ID
        self.ACCESS_KEY_SECRET = request.app.state.config.SMS_ACCESS_KEY_SECRET
        self.SIGN_NAME = request.app.state.config.SMS_SIGN_NAME
        self.TEMPLATE_CODE = request.app.state.config.SMS_TEMPLATE_CODE
        self.ENDPOINT = request.app.state.config.SMS_ENDPOINT


# 短信相关的Pydantic模型
class SendSMSForm(BaseModel):
    phone_number: str = Field(..., description="手机号码")
    type: Literal["login", "register", "bind"] = Field(
        ..., description="验证码类型: login-登录, register-注册, bind-绑定"
    )


class SMSRegisterForm(BaseModel):
    phone_number: str = Field(..., description="手机号码")
    verification_code: str = Field(..., description="验证码")
    password: str = Field(..., description="密码")
    name: str = Field(..., description="用户名")


class SMSLoginForm(BaseModel):
    phone_number: str = Field(..., description="手机号码")
    verification_code: str = Field(..., description="验证码")


# 微信登录相关的Pydantic模型
class WeChatLoginForm(BaseModel):
    openid: str = Field(..., description="微信openid")
    scene_id: str = Field(..., description="场景值")


class WeChatQRResponse(BaseModel):
    qr_code: str = Field(..., description="二维码图片base64")
    scene_id: str = Field(..., description="场景值")
    expires_in: int = Field(default=600, description="过期时间(秒)")


# 绑定手机号相关的Pydantic模型
class BindPhoneForm(BaseModel):
    phone_number: str = Field(..., description="手机号码")
    verification_code: str = Field(..., description="验证码")


class BindWeChatForm(BaseModel):
    openid: str = Field(..., description="微信openid")
    scene_id: str = Field(..., description="场景值")
    phone_number: Optional[str] = Field(None, description="待绑定的手机号")
    verification_code: Optional[str] = Field(None, description="手机验证码")
    name: Optional[str] = Field(None, description="用户姓名")
    password: Optional[str] = Field(None, description="密码")


# 短信服务类
class SMSService:
    @staticmethod
    def create_client(request: Request) -> Optional[DysmsapiClient]:
        """创建短信服务客户端"""
        if not SMS_AVAILABLE:
            log.error("短信SDK不可用：阿里云短信SDK未安装")
            return None

        try:
            sms_config = SMSConfig(request)

            # 添加配置参数检查和日志
            log.info(f"短信配置检查:")
            log.info(
                f"  ACCESS_KEY_ID: {'已配置' if sms_config.ACCESS_KEY_ID else '未配置'}"
            )
            log.info(
                f"  ACCESS_KEY_SECRET: {'已配置' if sms_config.ACCESS_KEY_SECRET else '未配置'}"
            )
            log.info(f"  SIGN_NAME: {sms_config.SIGN_NAME}")
            log.info(f"  TEMPLATE_CODE: {sms_config.TEMPLATE_CODE}")
            log.info(f"  ENDPOINT: {sms_config.ENDPOINT}")

            # 检查必要的配置参数
            if not sms_config.ACCESS_KEY_ID:
                log.error("短信配置错误：ACCESS_KEY_ID未配置")
                return None
            if not sms_config.ACCESS_KEY_SECRET:
                log.error("短信配置错误：ACCESS_KEY_SECRET未配置")
                return None
            if not sms_config.SIGN_NAME:
                log.error("短信配置错误：SIGN_NAME未配置")
                return None
            if not sms_config.TEMPLATE_CODE:
                log.error("短信配置错误：TEMPLATE_CODE未配置")
                return None

            config = open_api_models.Config(
                access_key_id=sms_config.ACCESS_KEY_ID,
                access_key_secret=sms_config.ACCESS_KEY_SECRET,
                endpoint=sms_config.ENDPOINT,
            )
            config.connect_timeout = 5000
            config.read_timeout = 10000

            client = DysmsapiClient(config)
            log.info("短信客户端创建成功")
            return client
        except Exception as e:
            log.error(f"创建短信客户端失败: {str(e)}")
            import traceback

            log.error(f"详细错误信息: {traceback.format_exc()}")
            return None

    @staticmethod
    def send_verification_sms(request: Request, phone_number: str, code: str) -> bool:
        """发送验证码短信"""
        if not SMS_AVAILABLE:
            log.error("短信SDK不可用：阿里云短信SDK未安装")
            return False

        try:
            log.info(f"开始发送短信验证码到手机号: {phone_number}")

            client = SMSService.create_client(request)
            if not client:
                log.error("短信客户端创建失败")
                return False

            sms_config = SMSConfig(request)

            # 创建短信发送请求
            sms_request = dysmsapi_models.SendSmsRequest(
                phone_numbers=phone_number,
                sign_name=sms_config.SIGN_NAME,
                template_code=sms_config.TEMPLATE_CODE,
                template_param=json.dumps({"code": code}),
            )

            log.info(f"短信请求参数:")
            log.info(f"  phone_numbers: {phone_number}")
            log.info(f"  sign_name: {sms_config.SIGN_NAME}")
            log.info(f"  template_code: {sms_config.TEMPLATE_CODE}")
            log.info(f"  template_param: {json.dumps({'code': code})}")

            runtime = util_models.RuntimeOptions()
            runtime.autoretry = True
            runtime.max_attempts = 3

            # 发送短信
            response = client.send_sms_with_options(sms_request, runtime)

            log.info(f"阿里云短信API响应:")
            log.info(f"  code: {response.body.code}")
            log.info(f"  message: {response.body.message}")
            log.info(f"  request_id: {response.body.request_id}")
            if hasattr(response.body, "biz_id"):
                log.info(f"  biz_id: {response.body.biz_id}")

            if response.body.code == "OK":
                log.info(f"短信发送成功，手机号: {phone_number}")
                return True
            else:
                log.error(
                    f"短信发送失败 - 错误码: {response.body.code}, 错误信息: {response.body.message}"
                )

                # 常见错误码解释
                error_codes = {
                    "isv.SMS_SIGNATURE_ILLEGAL": "短信签名不合法或未审核通过",
                    "isv.SMS_TEMPLATE_ILLEGAL": "短信模板不合法或未审核通过",
                    "isv.ACCOUNT_NOT_EXISTS": "账户不存在",
                    "isv.ACCOUNT_ABNORMAL": "账户异常",
                    "isv.SMS_CONTENT_ILLEGAL": "短信内容包含禁止发送内容",
                    "isv.SMS_SIGN_ILLEGAL": "短信签名不合法",
                    "isv.INVALID_PARAMETERS": "参数异常",
                    "isp.RAM_PERMISSION_DENY": "RAM权限DENY",
                    "isv.AMOUNT_NOT_ENOUGH": "账户余额不足",
                    "isv.TEMPLATE_MISSING_PARAMETERS": "模板缺少变量",
                    "isv.BUSINESS_LIMIT_CONTROL": "业务限流",
                    "isv.INVALID_JSON_PARAM": "JSON参数不合法",
                    "isv.MOBILE_NUMBER_ILLEGAL": "手机号码格式错误或为空",
                    "isv.MOBILE_COUNT_OVER_LIMIT": "手机号码数量超过限制",
                }

                error_explanation = error_codes.get(response.body.code, "未知错误")
                log.error(f"错误解释: {error_explanation}")

                return False

        except Exception as e:
            log.error(f"发送短信异常: {str(e)}")
            import traceback

            log.error(f"异常详情: {traceback.format_exc()}")
            return False


def generate_verification_code() -> str:
    """生成6位数字验证码"""
    return str(random.randint(100000, 999999))


def validate_phone_number(phone: str) -> bool:
    """验证手机号格式"""
    pattern = r"^1[3-9]\d{9}$"
    return bool(re.match(pattern, phone))


def store_verification_code(phone: str, code: str, type: str, expire_minutes: int = 5):
    """存储验证码（生产环境建议使用Redis）"""
    expire_time = time.time() + (expire_minutes * 60)
    sms_verification_codes[phone] = {
        "code": code,
        "type": type,
        "expire_time": expire_time,
        "attempts": 0,
    }


def verify_code(phone: str, code: str, type: str) -> bool:
    """验证验证码"""
    if phone not in sms_verification_codes:
        return False

    stored_data = sms_verification_codes[phone]

    # 检查类型是否匹配
    if stored_data["type"] != type:
        return False

    # 检查是否过期
    if time.time() > stored_data["expire_time"]:
        del sms_verification_codes[phone]
        return False

    # 检查尝试次数
    if stored_data["attempts"] >= 3:
        del sms_verification_codes[phone]
        return False

    # 验证码错误时增加尝试次数
    if stored_data["code"] != code:
        stored_data["attempts"] += 1
        return False

    # 验证成功，删除验证码
    del sms_verification_codes[phone]
    return True


# 微信公众号关注登录状态存储（生产环境建议使用Redis）
wechat_follow_states = {}


# 微信公众号关注登录服务类
class WeChatFollowService:
    @staticmethod
    def generate_scene_id() -> str:
        """生成场景值"""
        return hashlib.md5(
            f"{time.time()}{random.randint(1000, 9999)}".encode()
        ).hexdigest()[:8]

    @staticmethod
    async def create_qrcode_ticket(request: Request, scene_id: str) -> dict:
        """创建带参数的公众号二维码ticket"""
        app_id = request.app.state.config.WECHAT_APP_ID
        app_secret = request.app.state.config.WECHAT_APP_SECRET

        if not app_id or not app_secret:
            raise ValueError("微信公众号配置不完整")

        # 使用缓存的access_token
        access_token = await WeChatFollowService._get_cached_access_token(
            request, app_id, app_secret
        )

        # 创建带参数二维码（临时二维码，10分钟过期）
        qr_url = f"https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token={access_token}"
        qr_data = {
            "expire_seconds": 600,  # 10分钟过期
            "action_name": "QR_STR_SCENE",
            "action_info": {"scene": {"scene_str": scene_id}},
        }

        async with ClientSession() as session:
            async with session.post(qr_url, json=qr_data) as response:
                qr_response = await response.json()
                if "ticket" not in qr_response:
                    raise ValueError(
                        f"创建二维码失败: {qr_response.get('errmsg', '未知错误')}"
                    )

                return {
                    "ticket": qr_response["ticket"],
                    "expire_seconds": qr_response.get("expire_seconds", 600),
                    "url": qr_response.get("url", ""),
                }

    @staticmethod
    async def generate_qr_code(request: Request) -> WeChatQRResponse:
        """生成微信公众号关注二维码"""
        scene_id = WeChatFollowService.generate_scene_id()

        # 存储scene_id，用于验证
        wechat_follow_states[scene_id] = {
            "created_at": time.time(),
            "expires_at": time.time() + 600,  # 10分钟过期
            "status": "waiting",  # waiting, followed, login_success
        }

        try:
            # 调用微信API获取真实的ticket
            qr_data = await WeChatFollowService.create_qrcode_ticket(request, scene_id)
            ticket = qr_data["ticket"]

            # 直接从微信获取官方二维码图片
            import urllib.parse

            encoded_ticket = urllib.parse.quote(ticket)
            qr_image_url = (
                f"https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket={encoded_ticket}"
            )

            # 下载微信官方二维码图片
            async with ClientSession() as session:
                async with session.get(qr_image_url) as response:
                    if response.status == 200:
                        image_data = await response.read()
                        # 转换为base64
                        qr_base64 = base64.b64encode(image_data).decode()

                        return WeChatQRResponse(
                            qr_code=f"data:image/jpeg;base64,{qr_base64}",
                            scene_id=scene_id,
                            expires_in=qr_data.get("expire_seconds", 600),
                        )
                    else:
                        raise ValueError(
                            f"获取微信二维码图片失败，状态码: {response.status}"
                        )
        except Exception as e:
            log.error(f"生成公众号二维码失败: {str(e)}")
            raise ValueError(f"生成二维码失败: {str(e)}")

    # 缓存access_token和用户信息
    _access_token_cache = {"token": None, "expires_at": 0}
    _user_info_cache = {}

    @staticmethod
    async def get_wechat_user_info(request: Request, openid: str) -> dict:
        """获取微信用户信息（带缓存优化）"""
        app_id = request.app.state.config.WECHAT_APP_ID
        app_secret = request.app.state.config.WECHAT_APP_SECRET

        if not app_id or not app_secret:
            raise ValueError("微信公众号配置不完整")

        # 检查用户信息缓存
        cache_key = f"user_info_{openid}"
        if cache_key in WeChatFollowService._user_info_cache:
            cached_info = WeChatFollowService._user_info_cache[cache_key]
            if time.time() < cached_info.get("expires_at", 0):
                log.info(f"使用缓存的用户信息: {openid}")
                return cached_info["data"]

        # 获取或刷新access_token
        access_token = await WeChatFollowService._get_cached_access_token(
            request, app_id, app_secret
        )

        # 获取用户信息
        user_url = f"https://api.weixin.qq.com/cgi-bin/user/info?access_token={access_token}&openid={openid}&lang=zh_CN"

        async with ClientSession() as session:
            async with session.get(user_url) as response:
                user_data = await response.json()
                if "openid" not in user_data:
                    raise ValueError(
                        f"获取用户信息失败: {user_data.get('errmsg', '未知错误')}"
                    )

                # 处理空值和默认值
                processed_data = {
                    "subscribe": user_data.get("subscribe", 1),
                    "openid": user_data.get("openid", openid),
                    "nickname": user_data.get("nickname", "")
                    or f"微信用户_{openid[-8:]}",
                    "sex": user_data.get("sex", 0),
                    "language": user_data.get("language", "zh_CN"),
                    "city": user_data.get("city", ""),
                    "province": user_data.get("province", ""),
                    "country": user_data.get("country", ""),
                    "headimgurl": user_data.get("headimgurl", "") or "",
                    "subscribe_time": user_data.get("subscribe_time", int(time.time())),
                    "unionid": user_data.get("unionid", ""),
                    "remark": user_data.get("remark", ""),
                    "groupid": user_data.get("groupid", 0),
                    "tagid_list": user_data.get("tagid_list", []),
                    "subscribe_scene": user_data.get(
                        "subscribe_scene", "ADD_SCENE_QR_CODE"
                    ),
                    "qr_scene": user_data.get("qr_scene", 0),
                    "qr_scene_str": user_data.get("qr_scene_str", ""),
                }

                # 记录详细的调试信息
                log.info(f"原始微信用户信息: {user_data}")
                log.info(f"处理后的用户信息: {processed_data}")

                # 如果昵称和头像都为空，记录警告
                if (
                    not processed_data["nickname"]
                    or processed_data["nickname"] == f"微信用户_{openid[-8:]}"
                ):
                    log.warning(f"用户 {openid} 的昵称为空，可能是隐私设置限制")
                if not processed_data["headimgurl"]:
                    log.warning(f"用户 {openid} 的头像为空，可能是隐私设置限制")

                # 缓存用户信息（5分钟）
                WeChatFollowService._user_info_cache[cache_key] = {
                    "data": processed_data,
                    "expires_at": time.time() + 300,  # 5分钟缓存
                }

                return processed_data

    @staticmethod
    async def _get_cached_access_token(
        request: Request, app_id: str, app_secret: str
    ) -> str:
        """获取缓存的access_token"""
        current_time = time.time()

        # 检查缓存是否有效（access_token有效期2小时，我们提前5分钟刷新）
        if (
            WeChatFollowService._access_token_cache["token"]
            and current_time
            < WeChatFollowService._access_token_cache["expires_at"] - 300
        ):
            log.info("使用缓存的access_token")
            return WeChatFollowService._access_token_cache["token"]

        # 获取新的access_token
        log.info("获取新的access_token")
        token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={app_id}&secret={app_secret}"

        async with ClientSession() as session:
            async with session.get(token_url) as response:
                token_data = await response.json()
                if "access_token" not in token_data:
                    raise ValueError(
                        f"获取access_token失败: {token_data.get('errmsg', '未知错误')}"
                    )

                access_token = token_data["access_token"]
                expires_in = token_data.get("expires_in", 7200)  # 默认2小时

                # 更新缓存
                WeChatFollowService._access_token_cache = {
                    "token": access_token,
                    "expires_at": current_time + expires_in,
                }

                return access_token

    @staticmethod
    async def get_access_token(request: Request) -> str:
        """获取微信Access Token（使用缓存）"""
        app_id = request.app.state.config.WECHAT_APP_ID
        app_secret = request.app.state.config.WECHAT_APP_SECRET

        if not app_id or not app_secret:
            raise ValueError("微信公众号配置不完整")

        return await WeChatFollowService._get_cached_access_token(
            request, app_id, app_secret
        )

    @staticmethod
    async def send_text_message(request: Request, openid: str, content: str) -> bool:
        """发送文本消息给微信用户"""
        try:
            access_token = await WeChatFollowService.get_access_token(request)
            log.info(f"获取access_token成功")

            # 替换消息中的变量
            webui_url = request.app.state.config.WEBUI_URL
            content = content.replace("{WEBUI_URL}", webui_url)

            # 确保内容是正确的UTF-8字符串
            if isinstance(content, bytes):
                content = content.decode("utf-8")

            # 处理可能的Unicode转义序列
            try:
                # 如果内容包含Unicode转义序列，进行解码
                if "\\u" in content:
                    content = (
                        content.encode("utf-8")
                        .decode("unicode_escape")
                        .encode("latin1")
                        .decode("utf-8")
                    )
            except (UnicodeDecodeError, UnicodeEncodeError):
                # 如果解码失败，保持原内容
                pass

            send_url = f"https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={access_token}"

            message_data = {
                "touser": openid,
                "msgtype": "text",
                "text": {"content": content},
            }

            # 记录发送的消息内容以便调试
            log.info(f"准备发送消息给用户 {openid}，内容: {content}")

            async with ClientSession() as session:
                # 手动序列化JSON，确保UTF-8编码且不转义Unicode字符
                import json

                json_data = json.dumps(
                    message_data, ensure_ascii=False, separators=(",", ":")
                )

                async with session.post(
                    send_url,
                    data=json_data.encode("utf-8"),
                    headers={
                        "Content-Type": "application/json; charset=utf-8",
                        "Accept": "application/json",
                    },
                ) as response:
                    result = await response.json()
                    log.info(f"发送响应: {result}")
                    if result.get("errcode") == 0:
                        log.info(f"成功发送消息给用户 {openid}")
                        return True
                    else:
                        log.error(f"发送消息失败: {result}")
                        # 记录更详细的错误信息
                        error_code = result.get("errcode")
                        error_msg = result.get("errmsg", "未知错误")
                        log.error(f"错误代码: {error_code}, 错误信息: {error_msg}")
                        return False
        except Exception as e:
            log.error(f"发送微信消息异常: {str(e)}")
            import traceback

            log.error(f"异常详情: {traceback.format_exc()}")
            return False

    @staticmethod
    async def send_welcome_message(request: Request, openid: str) -> bool:
        """发送欢迎消息"""
        if not request.app.state.config.WECHAT_WELCOME_ENABLED:
            return True

        welcome_message = request.app.state.config.WECHAT_WELCOME_MESSAGE
        return await WeChatFollowService.send_text_message(
            request, openid, welcome_message
        )

    @staticmethod
    def find_keyword_reply(request: Request, message_content: str) -> str:
        """根据关键词找到对应的回复"""
        if not request.app.state.config.WECHAT_AUTO_REPLY_ENABLED:
            return None

        keyword_replies = request.app.state.config.WECHAT_KEYWORD_REPLIES

        message_lower = message_content.lower().strip()

        for reply_config in keyword_replies:
            keywords = reply_config.get("keywords", [])
            for keyword in keywords:
                if keyword.lower() in message_lower:
                    return reply_config.get("reply", "")

        # 如果没有匹配到关键词，返回默认回复
        return request.app.state.config.WECHAT_DEFAULT_REPLY_MESSAGE

    @staticmethod
    async def handle_user_message(
        request: Request, openid: str, message_content: str
    ) -> bool:
        """处理用户发送的消息"""
        reply_message = WeChatFollowService.find_keyword_reply(request, message_content)

        if reply_message:
            return await WeChatFollowService.send_text_message(
                request, openid, reply_message
            )

        return True

    @staticmethod
    def validate_scene_id(scene_id: str) -> bool:
        """验证场景值"""
        if scene_id not in wechat_follow_states:
            return False

        state_data = wechat_follow_states[scene_id]
        if time.time() > state_data["expires_at"]:
            del wechat_follow_states[scene_id]
            return False

        return True

    @staticmethod
    def mark_followed(scene_id: str, openid: str):
        """标记用户已关注"""
        if scene_id in wechat_follow_states:
            wechat_follow_states[scene_id]["status"] = "followed"
            wechat_follow_states[scene_id]["openid"] = openid

    @staticmethod
    def get_follow_status(scene_id: str) -> dict:
        """获取关注状态"""
        if scene_id not in wechat_follow_states:
            return {"status": "not_found"}

        state_data = wechat_follow_states[scene_id]
        if time.time() > state_data["expires_at"]:
            del wechat_follow_states[scene_id]
            return {"status": "expired"}

        return {"status": state_data["status"], "openid": state_data.get("openid")}

    @staticmethod
    def check_signature(token: str, timestamp: str, nonce: str, signature: str) -> bool:
        """验证微信GET请求签名"""
        if not all([token, timestamp, nonce, signature]):
            log.error(
                f"微信签名验证参数不完整: token={bool(token)}, timestamp={timestamp}, nonce={nonce}, signature={signature}"
            )
            return False

        # 微信签名验证算法：
        # 1. 将token、timestamp、nonce三个参数进行字典序排序
        # 2. 将三个参数字符串拼接成一个字符串
        # 3. 对这个字符串进行sha1加密
        # 4. 开发者获得加密后的字符串可与signature对比
        l = sorted([token, timestamp, nonce])
        s = "".join(l)
        computed_signature = hashlib.sha1(s.encode("utf-8")).hexdigest()

        log.info(f"微信签名验证详情:")
        log.info(f"  - token: {token}")
        log.info(f"  - timestamp: {timestamp}")
        log.info(f"  - nonce: {nonce}")
        log.info(f"  - 排序后拼接字符串: {s}")
        log.info(f"  - 计算出的签名: {computed_signature}")
        log.info(f"  - 微信传入的签名: {signature}")
        log.info(f"  - 签名是否匹配: {computed_signature == signature}")

        return computed_signature == signature

    @staticmethod
    def decrypt_message(
        request: Request,
        encrypted_xml: str,
        msg_signature: str,
        timestamp: str,
        nonce: str,
    ):
        """解密微信消息并验证签名"""
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome未安装，无法进行消息解密")

        token = request.app.state.config.WECHAT_TOKEN
        encoding_aes_key = request.app.state.config.WECHAT_AES_KEY
        app_id = request.app.state.config.WECHAT_APP_ID

        # 验证签名
        l = sorted([token, timestamp, nonce, encrypted_xml])
        s = "".join(l)
        local_signature = hashlib.sha1(s.encode("utf-8")).hexdigest()

        if msg_signature != local_signature:
            raise ValueError("消息签名验证失败")

        # 解密
        key = base64.b64decode(encoding_aes_key + "=")
        cipher = AES.new(key, AES.MODE_CBC, key[:16])
        plain_text = PKCS7Encoder.decode(
            cipher.decrypt(base64.b64decode(encrypted_xml))
        )

        # 提取并验证信息
        content = plain_text[16:]
        message_length = socket.ntohl(struct.unpack("I", content[:4])[0])
        message = content[4 : 4 + message_length].decode("utf-8")
        from_app_id = content[4 + message_length :].decode("utf-8")

        if from_app_id != app_id:
            raise ValueError("AppID不匹配")

        return message


############################
# GetSessionUser
############################


class SessionUserResponse(Token, UserResponse):
    expires_at: Optional[int] = None
    permissions: Optional[dict] = None
    credit: Decimal


@router.get("/", response_model=SessionUserResponse)
async def get_session_user(
    request: Request, response: Response, user: UserModel = Depends(get_current_user)
):
    auth_header = request.headers.get("Authorization")
    auth_token = get_http_authorization_cred(auth_header)
    token = auth_token.credentials
    data = decode_token(token)

    expires_at = None

    if data:
        expires_at = data.get("exp")

        if (expires_at is not None) and int(time.time()) > expires_at:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.INVALID_TOKEN,
            )

        # Set the cookie token
        response.set_cookie(
            key="token",
            value=token,
            expires=(
                datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
                if expires_at
                else None
            ),
            httponly=True,  # Ensures the cookie is not accessible via JavaScript
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
        )

    user_permissions = get_permissions(
        user.id, request.app.state.config.USER_PERMISSIONS
    )

    credit = Credits.init_credit_by_user_id(user.id)

    return {
        "token": token,
        "token_type": "Bearer",
        "expires_at": expires_at,
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "profile_image_url": user.profile_image_url,
        "permissions": user_permissions,
        "credit": credit.credit,
        "primary_login_type": user.primary_login_type,
        "available_login_types": user.available_login_types,
        "phone_number": user.phone_number,
        "wechat_openid": user.wechat_openid,
        "wechat_nickname": user.wechat_nickname,
        "binding_status": user.binding_status,
    }


############################
# 发送短信验证码
############################


@router.post("/sms/send")
async def send_sms_verification(request: Request, form_data: SendSMSForm):
    """发送短信验证码"""
    if not SMS_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="短信服务不可用，请联系管理员",
        )

    phone_number = form_data.phone_number.strip()

    # 验证手机号格式
    if not validate_phone_number(phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="手机号格式不正确"
        )

    # 检查验证码类型的具体逻辑
    if form_data.type == "register":
        # 注册验证码：检查手机号是否已有账号
        phone_auth = Auths.get_auth_by_phone_number(phone_number)
        bound_user = Users.get_user_by_phone_number(phone_number)

        if phone_auth or bound_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="该手机号已有关联账号，请使用登录功能",
            )

    elif form_data.type == "login":
        # 登录验证码：检查手机号是否已注册
        phone_user = Users.get_user_by_phone_number(phone_number)
        if not phone_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="该手机号尚未注册"
            )

    elif form_data.type == "bind":
        # 绑定验证码：检查手机号是否已被其他用户绑定
        phone_auth = Auths.get_auth_by_phone_number(phone_number)
        bound_user = Users.get_user_by_phone_number(phone_number)

        if phone_auth or bound_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="该手机号已被其他用户绑定",
            )

    # 检查是否频繁发送（1分钟内只能发送一次）
    if phone_number in sms_verification_codes:
        stored_data = sms_verification_codes[phone_number]
        if time.time() < stored_data["expire_time"] - 240:  # 5分钟-4分钟=1分钟
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="发送过于频繁，请稍后再试",
            )

    # 生成验证码
    verification_code = generate_verification_code()

    # 发送短信
    if SMSService.send_verification_sms(request, phone_number, verification_code):
        # 存储验证码
        store_verification_code(phone_number, verification_code, form_data.type)

        return {"success": True, "message": "验证码发送成功", "expire_minutes": 5}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="短信发送失败，请稍后重试",
        )


@router.post("/sms/register")
async def sms_register(
    request: Request, response: Response, form_data: SMSRegisterForm
):
    """短信验证码注册 - 验证手机号后要求绑定微信"""
    phone_number = form_data.phone_number.strip()
    verification_code = form_data.verification_code.strip()

    # 验证手机号格式
    if not validate_phone_number(phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="手机号格式不正确"
        )

    # 验证验证码
    if not verify_code(phone_number, verification_code, "register"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="验证码错误或已过期"
        )

    # 再次检查手机号是否已有账号（防止并发问题）
    phone_auth = Auths.get_auth_by_phone_number(phone_number)
    bound_user = Users.get_user_by_phone_number(phone_number)

    if phone_auth or bound_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="该手机号已有关联账号，请使用登录功能",
        )

    # 将已验证的手机号信息存储到临时字典中，等待微信绑定
    pending_phone_registrations[phone_number] = {
        "name": form_data.name,
        "password": form_data.password,
        "timestamp": time.time(),
        "verified": True,
    }

    # 清理超过30分钟的临时数据
    current_time = time.time()
    expired_phones = [
        phone
        for phone, data in pending_phone_registrations.items()
        if current_time - data["timestamp"] > 1800  # 30分钟
    ]
    for phone in expired_phones:
        del pending_phone_registrations[phone]

    return {
        "success": True,
        "message": "手机号验证成功，请绑定微信完成注册",
        "require_wechat_binding": True,
        "phone_number": phone_number,
    }


@router.post("/sms/signin", response_model=SessionUserResponse)
async def sms_signin(request: Request, response: Response, form_data: SMSLoginForm):
    """短信验证码登录"""
    phone_number = form_data.phone_number.strip()
    verification_code = form_data.verification_code.strip()

    # 验证手机号格式
    if not validate_phone_number(phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="手机号格式不正确"
        )

    # 验证验证码
    if not verify_code(phone_number, verification_code, "login"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="验证码错误或已过期"
        )

    # 查找用户
    user = Users.get_user_by_phone_number(phone_number)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="该手机号尚未注册"
        )

    # 生成JWT令牌
    expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
    expires_at = None
    if expires_delta:
        expires_at = int(time.time()) + int(expires_delta.total_seconds())

    token = create_token(
        data={"id": user.id},
        expires_delta=expires_delta,
    )

    datetime_expires_at = (
        datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
        if expires_at
        else None
    )

    # 设置Cookie
    response.set_cookie(
        key="token",
        value=token,
        expires=datetime_expires_at,
        httponly=True,
        samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
        secure=WEBUI_AUTH_COOKIE_SECURE,
    )

    # 获取用户权限
    user_permissions = get_permissions(
        user.id, request.app.state.config.USER_PERMISSIONS
    )

    # 初始化用户积分
    credit = Credits.init_credit_by_user_id(user.id)

    return {
        "token": token,
        "token_type": "Bearer",
        "expires_at": expires_at,
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "profile_image_url": user.profile_image_url,
        "permissions": user_permissions,
        "credit": credit.credit,
    }


############################
# 微信公众号关注登录
############################


@router.get("/wechat/qr")
async def get_wechat_follow_qr_code(request: Request):
    """获取微信公众号关注二维码"""
    if not request.app.state.config.ENABLE_WECHAT_LOGIN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="微信登录服务未启用"
        )

    try:
        qr_response = await WeChatFollowService.generate_qr_code(request)
        return {"success": True, "data": qr_response.dict()}
    except Exception as e:
        log.error(f"生成微信关注二维码失败: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"生成二维码失败: {str(e)}",
        )


@router.post("/wechat/follow-login")
async def wechat_follow_login(
    request: Request, response: Response, form_data: WeChatLoginForm
):
    """微信公众号关注登录"""
    if not request.app.state.config.ENABLE_WECHAT_LOGIN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="微信登录服务未启用"
        )

    try:
        # 验证scene_id参数
        if not WeChatFollowService.validate_scene_id(form_data.scene_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="无效的场景值或已过期",
            )

        # 获取微信用户信息
        try:
            user_info = await WeChatFollowService.get_wechat_user_info(
                request, form_data.openid
            )
            log.info(f"微信用户信息: {user_info}")

            if not user_info:
                raise ValueError("获取微信用户信息失败，返回空数据")

        except Exception as user_info_error:
            log.error(f"获取微信用户信息失败: {str(user_info_error)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"获取微信用户信息失败: {str(user_info_error)}",
            )

        # 使用微信openid查找用户
        user = Users.get_user_by_wechat_openid(form_data.openid)

        if user:
            # 用户已存在，检查绑定状态
            has_phone = bool(user.phone_number and user.phone_number.strip())
            has_wechat = bool(user.wechat_openid and user.wechat_openid.strip())

            log.info(
                f"用户绑定状态检查: user_id={user.id}, phone_number='{user.phone_number}', wechat_openid='{user.wechat_openid}', has_phone={has_phone}, has_wechat={has_wechat}"
            )

            # 如果用户已有微信绑定但未绑定手机号，提示绑定手机号但允许直接登录
            if has_wechat and not has_phone:
                # 微信已绑定但未绑定手机号，建议绑定手机号但可以直接登录
                log.info(f"微信用户未绑定手机号，建议绑定但允许登录: {user.email}")

                # 可以选择直接登录或要求绑定手机号
                # 这里根据业务需求决定：如果要求必须绑定手机号，返回需要绑定的响应
                # 如果允许仅微信登录，继续执行登录流程

                # 根据配置决定是否要求强制绑定手机号
                require_phone_binding = getattr(
                    request.app.state.config, "REQUIRE_PHONE_BINDING_FOR_WECHAT", False
                )

                if require_phone_binding:
                    return {
                        "success": False,
                        "need_phone_binding": True,
                        "openid": form_data.openid,
                        "scene_id": form_data.scene_id,
                        "user_info": {
                            "id": user.id,
                            "name": user.name,
                            "profile_image_url": user.profile_image_url,
                            "wechat_nickname": user.wechat_nickname
                            or user_info.get("nickname", ""),
                        },
                        "message": "建议绑定手机号以获得更好的账号安全保护",
                    }
                # 否则继续登录流程

            elif not has_wechat:
                # 如果用户没有微信绑定信息，需要更新
                log.warning(f"用户缺少微信绑定信息，更新中: user_id={user.id}")
                Users.update_user_by_id(
                    user.id,
                    {
                        "wechat_openid": form_data.openid,
                        "wechat_nickname": user_info.get("nickname", ""),
                    },
                )
                # 同时更新Auth表
                Auths.update_auth_binding_info(
                    user_id=user.id,
                    login_type="wechat",
                    wechat_openid=form_data.openid,
                    auth_metadata=user_info,
                )
                # 重新获取用户信息
                user = Users.get_user_by_id(user.id)

            # 继续登录流程
            log.info(f"微信用户登录: {user.email}, 手机号绑定状态: {has_phone}")
        else:
            # 用户不存在，但需要检查是否有重复账号

            # 1. 检查该微信openid是否已经绑定到其他用户
            existing_wechat_user = Users.get_user_by_wechat_openid(form_data.openid)
            if existing_wechat_user:
                log.warning(
                    f"微信openid {form_data.openid} 已绑定到其他用户: {existing_wechat_user.id}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="该微信账号已绑定其他用户，请使用正确的登录方式或联系管理员",
                )

            # 2. 检查微信用户的手机号是否已被其他账号使用（如果微信提供了手机号信息）
            wechat_phone = user_info.get("phone_number") or user_info.get("mobile")
            if wechat_phone:
                wechat_phone = wechat_phone.strip()
                if wechat_phone and validate_phone_number(wechat_phone):
                    # 检查手机号是否已被注册
                    phone_auth = Auths.get_auth_by_phone_number(wechat_phone)
                    bound_user = Users.get_user_by_phone_number(wechat_phone)

                    if phone_auth or bound_user:
                        existing_user = (
                            bound_user or Users.get_user_by_id(phone_auth.id)
                            if phone_auth
                            else None
                        )
                        log.warning(
                            f"微信用户的手机号 {wechat_phone} 已被用户 {existing_user.id if existing_user else 'unknown'} 使用"
                        )

                        # 返回需要绑定手机号的响应，但提示手机号冲突
                        return {
                            "success": False,
                            "need_phone_binding": True,
                            "phone_conflict": True,
                            "openid": form_data.openid,
                            "scene_id": form_data.scene_id,
                            "message": f"检测到您的微信绑定的手机号 {wechat_phone[:3]}****{wechat_phone[-4:]} 已有关联账号，请使用其他手机号完成注册或登录已有账号",
                        }

            # 3. 没有冲突，创建新用户
            user_count = Users.get_num_users()
            role = (
                "admin"
                if user_count == 0
                else request.app.state.config.DEFAULT_USER_ROLE
            )

            # 使用微信昵称作为用户名，如果为空则使用默认名称
            nickname = user_info.get("nickname", "")
            if not nickname or nickname == f"微信用户_{form_data.openid[-8:]}":
                nickname = f"微信用户_{form_data.openid[-8:]}"

            profile_image_url = user_info.get("headimgurl", "")

            # 如果没有头像，使用默认头像生成逻辑
            if not profile_image_url:
                import hashlib

                avatar_hash = hashlib.md5(form_data.openid.encode()).hexdigest()
                profile_image_url = (
                    f"https://www.gravatar.com/avatar/{avatar_hash}?d=identicon&s=200"
                )

            log.info(
                f"创建微信用户: nickname={nickname}, profile_image_url={profile_image_url}"
            )

            try:
                user = Auths.insert_new_auth(
                    email=None,  # 不使用伪邮箱
                    password=str(uuid.uuid4()),  # 随机密码，微信用户不使用密码登录
                    name=nickname,
                    role=role,
                    profile_image_url=profile_image_url,
                    login_type="wechat",
                    external_id=form_data.openid,
                    wechat_openid=form_data.openid,
                    auth_metadata=user_info,
                )

                log.info(f"Auths.insert_new_auth 返回结果: {user}")

                if not user:
                    log.error(f"创建微信用户失败，Auths.insert_new_auth 返回了 None")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="创建用户失败",
                    )

                # 验证微信字段是否正确设置
                if not user.wechat_openid:
                    log.warning(
                        f"新创建的用户缺少微信openid，手动设置: user_id={user.id}"
                    )
                    # 手动更新Auth表中的微信字段
                    Auths.update_auth_binding_info(
                        user_id=user.id,
                        login_type="wechat",
                        wechat_openid=form_data.openid,
                        auth_metadata=user_info,
                    )
                    # 重新获取用户信息
                    user = Users.get_user_by_id(user.id)
            except Exception as insert_error:
                log.error(f"调用 Auths.insert_new_auth 时发生异常: {str(insert_error)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"创建用户失败: {str(insert_error)}",
                )

            # 新创建的用户需要绑定手机号
            return {
                "success": False,
                "need_phone_binding": True,
                "openid": form_data.openid,
                "scene_id": form_data.scene_id,
                "user_info": {
                    "id": user.id,
                    "name": user.name,
                    "profile_image_url": user.profile_image_url,
                    "wechat_nickname": user.wechat_nickname or nickname,
                },
                "message": "账号创建成功，请绑定手机号完成注册",
            }

        # 到这里说明用户存在且已绑定手机号，进行登录流程
        # 更新用户的头像和昵称
        nickname = user_info.get("nickname", "")
        if nickname and nickname != f"微信用户_{form_data.openid[-8:]}":
            profile_image_url = user_info.get("headimgurl", "")
            if not profile_image_url and user.profile_image_url:
                profile_image_url = user.profile_image_url

            Users.update_user_by_id(
                user.id,
                {
                    "wechat_nickname": nickname,
                    "profile_image_url": profile_image_url or user.profile_image_url,
                },
            )
            # 重新获取更新后的用户信息
            user = Users.get_user_by_id(user.id)

        # 生成JWT令牌
        expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
        expires_at = None
        if expires_delta:
            expires_at = int(time.time()) + int(expires_delta.total_seconds())

        token = create_token(
            data={"id": user.id},
            expires_delta=expires_delta,
        )

        datetime_expires_at = (
            datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
            if expires_at
            else None
        )

        # 设置Cookie
        response.set_cookie(
            key="token",
            value=token,
            expires=datetime_expires_at,
            httponly=True,
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
        )

        # 获取用户权限
        user_permissions = get_permissions(
            user.id, request.app.state.config.USER_PERMISSIONS
        )

        # 初始化用户积分
        credit = Credits.init_credit_by_user_id(user.id)

        # 清理场景值
        if form_data.scene_id in wechat_follow_states:
            del wechat_follow_states[form_data.scene_id]

        return {
            "success": True,
            "token": token,
            "token_type": "Bearer",
            "expires_at": expires_at,
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "profile_image_url": user.profile_image_url,
            "permissions": user_permissions,
            "credit": credit.credit,
            "phone_number": user.phone_number,
            "wechat_openid": user.wechat_openid,
            "wechat_nickname": user.wechat_nickname,
            "primary_login_type": user.primary_login_type,
            "available_login_types": user.available_login_types,
            "binding_status": user.binding_status,
        }

    except HTTPException as http_exc:
        # 重新抛出已经处理过的HTTP异常
        log.error(f"微信登录HTTP异常: {http_exc.detail}")
        raise
    except Exception as e:
        log.error(f"微信登录失败: {str(e)}")
        import traceback

        log.error(f"异常详情: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"登录失败: {str(e)}",
        )


@router.post("/wechat/follow-event")
async def wechat_follow_event(request: Request):
    """处理微信公众号关注事件（微信服务器回调）"""
    try:
        # 从URL查询参数获取签名信息
        signature = request.query_params.get("signature", "")
        msg_signature = request.query_params.get("msg_signature", "")
        timestamp = request.query_params.get("timestamp", "")
        nonce = request.query_params.get("nonce", "")

        body = await request.body()
        xml_data = body.decode("utf-8")

        log.info(f"收到微信事件回调:")
        log.info(f"  - signature: {signature}")
        log.info(f"  - msg_signature: {msg_signature}")
        log.info(f"  - timestamp: {timestamp}")
        log.info(f"  - nonce: {nonce}")
        log.info(f"  - xml_data: {xml_data}")

        root = ET.fromstring(xml_data)

        # 首先尝试从明文部分获取信息（兼容模式下明文可用）
        msg_type = root.find("MsgType").text if root.find("MsgType") is not None else ""

        if msg_type:
            # 明文模式或兼容模式下的明文部分可用
            log.info("检测到明文消息，直接解析...")
        else:
            # 检查是否是纯加密消息
            encrypted_element = root.find("Encrypt")

            if encrypted_element is not None and encrypted_element.text:
                # 处理纯加密消息
                log.info("检测到纯加密消息，开始解密...")
                encrypted_message = encrypted_element.text

                # 解密消息
                decrypted_xml = WeChatFollowService.decrypt_message(
                    request, encrypted_message, msg_signature, timestamp, nonce
                )

                log.info(f"解密后的XML: {decrypted_xml}")

                # 解析解密后的XML
                root = ET.fromstring(decrypted_xml)
            else:
                log.error("无法识别的消息格式")
                return Response(content="success", media_type="text/plain")

        # 提取关键信息（如果之前没有提取过msg_type则重新提取）
        if not msg_type:
            msg_type = (
                root.find("MsgType").text if root.find("MsgType") is not None else ""
            )

        event = root.find("Event").text if root.find("Event") is not None else ""
        openid = (
            root.find("FromUserName").text
            if root.find("FromUserName") is not None
            else ""
        )
        scene_str = (
            root.find("EventKey").text if root.find("EventKey") is not None else ""
        )

        log.info(f"解析出的事件信息:")
        log.info(f"  - MsgType: {msg_type}")
        log.info(f"  - Event: {event}")
        log.info(f"  - FromUserName (openid): {openid}")
        log.info(f"  - EventKey: {scene_str}")

        # 处理关注事件
        if msg_type == "event" and event == "subscribe":
            if scene_str.startswith("qrscene_"):
                scene_id = scene_str[8:]  # 去掉qrscene_前缀
                WeChatFollowService.mark_followed(scene_id, openid)
                log.info(f"用户 {openid} 通过场景值 {scene_id} 关注了公众号")
                log.info(f"已标记场景值 {scene_id} 为已关注状态")

                # 发送欢迎消息
                try:
                    await WeChatFollowService.send_welcome_message(request, openid)
                except Exception as e:
                    log.error(f"发送欢迎消息失败: {str(e)}")
            else:
                log.info(f"用户 {openid} 关注了公众号（无场景值）")

                # 发送欢迎消息
                try:
                    await WeChatFollowService.send_welcome_message(request, openid)
                except Exception as e:
                    log.error(f"发送欢迎消息失败: {str(e)}")

        # 处理扫描事件（已关注用户扫描带参数二维码）
        elif msg_type == "event" and event == "SCAN":
            scene_id = scene_str
            WeChatFollowService.mark_followed(scene_id, openid)
            log.info(f"已关注用户 {openid} 扫描了场景值 {scene_id} 的二维码")
            log.info(f"已标记场景值 {scene_id} 为已关注状态")

            # 发送欢迎消息（SCAN事件也应该发送）
            try:
                await WeChatFollowService.send_welcome_message(request, openid)
                log.info(f"成功发送欢迎消息给已关注用户 {openid}")
            except Exception as e:
                log.error(f"发送欢迎消息失败: {str(e)}")

        # 处理文本消息
        elif msg_type == "text":
            content = (
                root.find("Content").text if root.find("Content") is not None else ""
            )
            log.info(f"收到用户 {openid} 的文本消息: {content}")

            # 处理用户消息并自动回复
            try:
                await WeChatFollowService.handle_user_message(request, openid, content)
            except Exception as e:
                log.error(f"处理用户消息失败: {str(e)}")

        else:
            log.info(f"收到其他类型的事件: MsgType={msg_type}, Event={event}")

        return Response(content="success", media_type="text/plain")

    except Exception as e:
        log.error(f"处理微信关注事件失败: {str(e)}")
        import traceback

        log.error(f"错误详情: {traceback.format_exc()}")
        return Response(content="success", media_type="text/plain")


@router.get("/wechat/follow-event")
async def wechat_server_verification(request: Request):
    """处理微信服务器URL验证（GET请求）"""
    try:
        signature = request.query_params.get("signature", "")
        timestamp = request.query_params.get("timestamp", "")
        nonce = request.query_params.get("nonce", "")
        echostr = request.query_params.get("echostr", "")
        token = request.app.state.config.WECHAT_TOKEN
        print(f"收到微信服务器验证请求:")
        log.info(f"收到微信服务器验证请求:")
        log.info(f"  - signature: {signature}")
        log.info(f"  - timestamp: {timestamp}")
        log.info(f"  - nonce: {nonce}")
        log.info(f"  - echostr: {echostr}")
        log.info(f"  - 配置的token: {token}")

        if not token:
            log.error("微信TOKEN未配置")
            raise HTTPException(
                status_code=500, detail="服务器配置错误: 微信TOKEN未设置"
            )

        if WeChatFollowService.check_signature(token, timestamp, nonce, signature):
            log.info(f"微信签名验证成功，返回echostr: {echostr}")
            return Response(content=echostr, media_type="text/plain")
        else:
            log.error("微信签名验证失败")
            raise HTTPException(status_code=403, detail="签名验证失败")
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"微信服务器验证异常: {str(e)}")
        raise HTTPException(status_code=500, detail="服务器内部错误")


@router.get("/wechat/check/{scene_id}")
async def check_wechat_follow_status(scene_id: str):
    """检查微信关注状态（用于前端轮询）"""
    try:
        status_data = WeChatFollowService.get_follow_status(scene_id)
        return status_data
    except Exception as e:
        log.error(f"检查微信关注状态失败: {str(e)}")
        return {"status": "error", "message": str(e)}


@router.get("/wechat/debug/config")
async def debug_wechat_config(request: Request):
    """调试微信配置信息（仅用于调试）"""
    try:
        config = {
            "ENABLE_WECHAT_LOGIN": request.app.state.config.ENABLE_WECHAT_LOGIN,
            "WECHAT_APP_ID": request.app.state.config.WECHAT_APP_ID,
            "WECHAT_APP_SECRET": (
                "***" if request.app.state.config.WECHAT_APP_SECRET else ""
            ),
            "WECHAT_TOKEN": "***" if request.app.state.config.WECHAT_TOKEN else "",
            "WECHAT_AES_KEY": "***" if request.app.state.config.WECHAT_AES_KEY else "",
            "callback_url": f"/api/v1/auths/wechat/follow-event",
            "current_follow_states_count": len(wechat_follow_states),
            "active_scenes": (
                list(wechat_follow_states.keys()) if wechat_follow_states else []
            ),
            # 添加消息推送配置信息
            "WECHAT_WELCOME_ENABLED": request.app.state.config.WECHAT_WELCOME_ENABLED,
            "WECHAT_AUTO_REPLY_ENABLED": request.app.state.config.WECHAT_AUTO_REPLY_ENABLED,
        }
        return {"status": "success", "config": config}
    except Exception as e:
        log.error(f"获取微信调试配置失败: {str(e)}")
        return {"status": "error", "message": str(e)}


class WeChatTestMessageForm(BaseModel):
    openid: str = Field(..., description="测试用户的OpenID")
    message: str = Field(..., description="测试消息内容")


@router.post("/wechat/test/message")
async def test_wechat_message(
    request: Request, form_data: WeChatTestMessageForm, user=Depends(get_admin_user)
):
    """测试微信消息发送（仅管理员）"""
    try:
        success = await WeChatFollowService.send_text_message(
            request, form_data.openid, form_data.message
        )
        if success:
            return {"status": "success", "message": "测试消息发送成功"}
        else:
            return {"status": "error", "message": "测试消息发送失败"}
    except Exception as e:
        log.error(f"测试微信消息发送失败: {str(e)}")
        return {"status": "error", "message": str(e)}


############################
# 检查手机号是否已存在接口
############################


class CheckPhoneForm(BaseModel):
    phone_number: str = Field(..., description="手机号码")


@router.post("/check/phone")
async def check_phone_exists(form_data: CheckPhoneForm):
    """检查手机号是否已存在"""
    phone_number = form_data.phone_number.strip()

    # 验证手机号格式
    if not validate_phone_number(phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="手机号格式不正确"
        )

    # 检查手机号是否已被绑定（通过手机号字段检查）
    bound_user = Users.get_user_by_phone_number(phone_number)

    # 检查认证表中的手机号记录
    phone_auth = Auths.get_auth_by_phone_number(phone_number)

    result = {
        "phone_number": phone_number,
        "exists": False,
        "details": {
            "registered_as_primary": False,  # 作为主要登录方式注册
            "bound_to_other_account": False,  # 绑定到其他账号
            "user_info": None,
        },
    }

    if bound_user:
        result["exists"] = True
        result["details"]["bound_to_other_account"] = True
        result["details"]["user_info"] = {
            "id": bound_user.id,
            "name": bound_user.name,
            "email": bound_user.email,
            "primary_login_type": bound_user.primary_login_type,
            "wechat_openid": bound_user.wechat_openid,
            "wechat_nickname": bound_user.wechat_nickname,
        }
    elif phone_auth:
        # 通过认证表找到的用户
        auth_user = Users.get_user_by_id(phone_auth.id)
        if auth_user:
            result["exists"] = True
            result["details"]["bound_to_other_account"] = True
            result["details"]["user_info"] = {
                "id": auth_user.id,
                "name": auth_user.name,
                "email": auth_user.email,
                "primary_login_type": auth_user.primary_login_type,
                "wechat_openid": auth_user.wechat_openid,
                "wechat_nickname": auth_user.wechat_nickname,
            }

    return result


############################
# 绑定手机号接口
############################


@router.post("/bind/phone")
async def bind_phone_number(
    request: Request, form_data: BindPhoneForm, user=Depends(get_current_user)
):
    """绑定手机号"""
    phone_number = form_data.phone_number.strip()
    verification_code = form_data.verification_code.strip()

    # 验证手机号格式
    if not validate_phone_number(phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="手机号格式不正确"
        )

    # 验证验证码
    if not verify_code(phone_number, verification_code, "bind"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="验证码错误或已过期"
        )

    # 检查手机号是否已被其他用户绑定
    phone_auth = Auths.get_auth_by_phone_number(phone_number)
    existing_user = Users.get_user_by_phone_number(phone_number)
    if (phone_auth and phone_auth.id != user.id) or (
        existing_user and existing_user.id != user.id
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="该手机号已被其他用户绑定"
        )

    try:
        # 直接更新用户的手机号信息，不区分登录类型
        current_login_types = getattr(user, "available_login_types", "") or getattr(
            user, "primary_login_type", "email"
        )
        new_login_types = current_login_types
        if "phone" not in current_login_types:
            new_login_types = (
                f"{current_login_types},phone" if current_login_types else "phone"
            )

        Users.update_user_by_id(
            user.id,
            {
                "phone_number": phone_number,
                "available_login_types": new_login_types,
                "binding_status": {
                    **getattr(user, "binding_status", {}),
                    "phone": "active",
                },
            },
        )

        # 更新认证表的手机号信息
        Auths.update_auth_binding_info(user.id, "phone", phone_number=phone_number)

        return {"success": True, "message": "手机号绑定成功"}
    except Exception as e:
        log.error(f"绑定手机号失败: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="绑定失败"
        )


############################
# 绑定微信接口
############################


@router.post("/bind/wechat")
async def bind_wechat(
    request: Request,
    response: Response,
    form_data: BindWeChatForm,
    user=Depends(get_current_user),
):
    """绑定微信"""
    openid = form_data.openid.strip()
    scene_id = form_data.scene_id.strip()

    # 验证场景值
    if not WeChatFollowService.validate_scene_id(scene_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="无效的场景值或已过期"
        )

    # 检查微信是否已被其他用户绑定
    wechat_auth = Auths.get_auth_by_wechat_openid(openid)
    existing_user = Users.get_user_by_wechat_openid(openid)
    if (wechat_auth and wechat_auth.id != user.id) or (
        existing_user and existing_user.id != user.id
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="该微信账号已被其他用户绑定"
        )

    try:
        # 获取微信用户信息
        user_info = await WeChatFollowService.get_wechat_user_info(request, openid)

        # 直接更新用户的微信绑定信息，不区分登录类型
        current_login_types = getattr(user, "available_login_types", "") or getattr(
            user, "primary_login_type", "email"
        )
        new_login_types = current_login_types
        if "wechat" not in current_login_types:
            new_login_types = (
                f"{current_login_types},wechat" if current_login_types else "wechat"
            )

        Users.update_user_by_id(
            user.id,
            {
                "wechat_openid": openid,
                "wechat_nickname": user_info.get("nickname"),
                "available_login_types": new_login_types,
                "binding_status": {
                    **getattr(user, "binding_status", {}),
                    "wechat": "active",
                },
            },
        )

        # 更新认证表的微信信息
        Auths.update_auth_binding_info(
            user.id,
            "wechat",
            wechat_openid=openid,
            wechat_unionid=user_info.get("unionid"),
            auth_metadata=user_info,
        )

        # 清理场景值
        if scene_id in wechat_follow_states:
            del wechat_follow_states[scene_id]

        return {"success": True, "message": "微信绑定成功"}

    except Exception as e:
        log.error(f"绑定微信失败: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="绑定失败"
        )


############################
# 手机号注册绑定微信接口
############################


@router.post("/register/wechat", response_model=SessionUserResponse)
async def register_with_wechat_binding(
    request: Request, response: Response, form_data: BindWeChatForm
):
    """手机号注册用户绑定微信完成注册"""
    if not (
        form_data.phone_number
        and form_data.verification_code
        and form_data.name
        and form_data.password
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="缺少必要的注册信息"
        )

    openid = form_data.openid.strip()
    scene_id = form_data.scene_id.strip()
    phone_number = form_data.phone_number.strip()
    verification_code = form_data.verification_code.strip()

    # 验证场景值
    if not WeChatFollowService.validate_scene_id(scene_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="无效的场景值或已过期"
        )

    # 验证手机号格式
    if not validate_phone_number(phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="手机号格式不正确"
        )

    # 检查是否有待绑定的手机号数据
    if phone_number not in pending_phone_registrations:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="手机号验证已过期，请重新验证",
        )

    pending_data = pending_phone_registrations[phone_number]

    # 获取微信用户信息
    user_info = await WeChatFollowService.get_wechat_user_info(request, openid)

    try:
        # 检查并处理账号合并
        merge_result = Auths.check_and_merge_wechat_phone_binding(
            phone_number=phone_number,
            wechat_openid=openid,
            wechat_nickname=user_info.get("nickname"),
            auth_metadata=user_info,
        )

        final_user = None

        if merge_result["action"] == "create_new":
            # 创建新账号（同时绑定手机号和微信）
            user_count = Users.get_num_users()
            role = (
                "admin"
                if user_count == 0
                else request.app.state.config.DEFAULT_USER_ROLE
            )

            # 合并微信信息到用户名和头像
            user_name = pending_data["name"]
            user_profile_image = user_info.get("headimgurl", "")
            if not user_profile_image:
                import hashlib

                avatar_hash = hashlib.md5(openid.encode()).hexdigest()
                user_profile_image = (
                    f"https://www.gravatar.com/avatar/{avatar_hash}?d=identicon&s=200"
                )

            hashed = get_password_hash(pending_data["password"])

            # 创建新用户，不使用伪邮箱
            final_user = Auths.insert_new_auth(
                email=None,  # 不设置邮箱，使用自有字段
                password=hashed,
                name=user_name,
                role=role,
                profile_image_url=user_profile_image,
                login_type="phone",  # 主要登录方式为手机号
                phone_number=phone_number,
                wechat_openid=openid,
                wechat_unionid=user_info.get("unionid"),
                auth_metadata=user_info,
            )

            if not final_user:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="用户创建失败",
                )

            # 验证创建的用户字段是否正确
            log.info(
                f"验证新创建的用户字段: user_id={final_user.id}, phone_number={final_user.phone_number}, wechat_openid={final_user.wechat_openid}"
            )

            # 如果缺少字段，手动补充
            missing_fields = []
            if not final_user.phone_number:
                missing_fields.append("phone_number")
            if not final_user.wechat_openid:
                missing_fields.append("wechat_openid")

            if missing_fields:
                log.warning(f"新创建的用户缺少字段: {missing_fields}，手动补充")
                # 手动更新Auth表中缺少的字段
                if "phone_number" in missing_fields:
                    Auths.update_auth_binding_info(
                        user_id=final_user.id,
                        login_type="phone",
                        phone_number=phone_number,
                    )
                if "wechat_openid" in missing_fields:
                    Auths.update_auth_binding_info(
                        user_id=final_user.id,
                        login_type="wechat",
                        wechat_openid=openid,
                        wechat_unionid=user_info.get("unionid"),
                        auth_metadata=user_info,
                    )
                # 重新获取用户信息
                final_user = Users.get_user_by_id(final_user.id)

            # 更新用户绑定信息
            Users.update_user_by_id(
                final_user.id,
                {
                    "available_login_types": "phone,wechat",
                    "wechat_nickname": user_info.get("nickname"),
                    "binding_status": {"phone": "active", "wechat": "active"},
                },
            )

        elif merge_result["action"] in [
            "merge_to_wechat",
            "merge_to_phone",
            "same_account",
        ]:
            # 账号合并成功或已是同一账号
            final_user = merge_result["user"]

            # 如果是合并到微信账号，需要设置密码（如果微信账号没有密码）
            if merge_result["action"] == "merge_to_wechat":
                hashed = get_password_hash(pending_data["password"])
                Auths.update_user_password_by_id(final_user.id, hashed)

                # 更新用户名（如果需要）
                Users.update_user_by_id(
                    final_user.id,
                    {
                        "name": pending_data["name"],
                        "available_login_types": "phone,wechat",
                        "binding_status": {"phone": "active", "wechat": "active"},
                    },
                )

        else:
            # 冲突或错误
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=merge_result["message"],
            )

        if not final_user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="账号处理失败",
            )

        # 重新获取更新后的用户信息
        final_user = Users.get_user_by_id(final_user.id)

        # 生成JWT令牌
        expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
        expires_at = None
        if expires_delta:
            expires_at = int(time.time()) + int(expires_delta.total_seconds())

        token = create_token(
            data={"id": final_user.id},
            expires_delta=expires_delta,
        )

        datetime_expires_at = (
            datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
            if expires_at
            else None
        )

        # 设置Cookie
        response.set_cookie(
            key="token",
            value=token,
            expires=datetime_expires_at,
            httponly=True,
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
        )

        # 获取用户权限
        user_permissions = get_permissions(
            final_user.id, request.app.state.config.USER_PERMISSIONS
        )

        # 初始化用户积分
        credit = Credits.init_credit_by_user_id(final_user.id)

        # 清理临时数据
        del pending_phone_registrations[phone_number]

        # 清理场景值
        if scene_id in wechat_follow_states:
            del wechat_follow_states[scene_id]

        return {
            "token": token,
            "token_type": "Bearer",
            "expires_at": expires_at,
            "id": final_user.id,
            "email": final_user.email,
            "name": final_user.name,
            "role": final_user.role,
            "profile_image_url": final_user.profile_image_url,
            "permissions": user_permissions,
            "credit": credit.credit,
            "phone_number": final_user.phone_number,
            "wechat_openid": final_user.wechat_openid,
            "wechat_nickname": final_user.wechat_nickname,
            "primary_login_type": final_user.primary_login_type,
            "available_login_types": final_user.available_login_types,
            "binding_status": final_user.binding_status,
        }

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"手机号注册绑定微信失败: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"注册失败: {str(e)}",
        )


############################
# Update Profile
############################


@router.post("/update/profile", response_model=UserResponse)
async def update_profile(
    form_data: UpdateProfileForm, session_user=Depends(get_verified_user)
):
    if session_user:
        user = Users.update_user_by_id(
            session_user.id,
            {"profile_image_url": form_data.profile_image_url, "name": form_data.name},
        )
        if user:
            return user
        else:
            raise HTTPException(400, detail=ERROR_MESSAGES.DEFAULT())
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)


############################
# Update Password
############################


@router.post("/update/password", response_model=bool)
async def update_password(
    form_data: UpdatePasswordForm, session_user=Depends(get_current_user)
):
    if WEBUI_AUTH_TRUSTED_EMAIL_HEADER:
        raise HTTPException(400, detail=ERROR_MESSAGES.ACTION_PROHIBITED)
    if session_user:
        user = Auths.authenticate_user(session_user.email, form_data.password)

        if user:
            hashed = get_password_hash(form_data.new_password)
            return Auths.update_user_password_by_id(user.id, hashed)
        else:
            raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_PASSWORD)
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)


############################
# LDAP Authentication
############################
@router.post("/ldap", response_model=SessionUserResponse)
async def ldap_auth(request: Request, response: Response, form_data: LdapForm):
    ENABLE_LDAP = request.app.state.config.ENABLE_LDAP
    LDAP_SERVER_LABEL = request.app.state.config.LDAP_SERVER_LABEL
    LDAP_SERVER_HOST = request.app.state.config.LDAP_SERVER_HOST
    LDAP_SERVER_PORT = request.app.state.config.LDAP_SERVER_PORT
    LDAP_ATTRIBUTE_FOR_MAIL = request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL
    LDAP_ATTRIBUTE_FOR_USERNAME = request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME
    LDAP_SEARCH_BASE = request.app.state.config.LDAP_SEARCH_BASE
    LDAP_SEARCH_FILTERS = request.app.state.config.LDAP_SEARCH_FILTERS
    LDAP_APP_DN = request.app.state.config.LDAP_APP_DN
    LDAP_APP_PASSWORD = request.app.state.config.LDAP_APP_PASSWORD
    LDAP_USE_TLS = request.app.state.config.LDAP_USE_TLS
    LDAP_CA_CERT_FILE = request.app.state.config.LDAP_CA_CERT_FILE
    LDAP_CIPHERS = (
        request.app.state.config.LDAP_CIPHERS
        if request.app.state.config.LDAP_CIPHERS
        else "ALL"
    )

    if not ENABLE_LDAP:
        raise HTTPException(400, detail="LDAP authentication is not enabled")

    try:
        tls = Tls(
            validate=CERT_REQUIRED,
            version=PROTOCOL_TLS,
            ca_certs_file=LDAP_CA_CERT_FILE,
            ciphers=LDAP_CIPHERS,
        )
    except Exception as e:
        log.error(f"TLS configuration error: {str(e)}")
        raise HTTPException(400, detail="Failed to configure TLS for LDAP connection.")

    try:
        server = Server(
            host=LDAP_SERVER_HOST,
            port=LDAP_SERVER_PORT,
            get_info=NONE,
            use_ssl=LDAP_USE_TLS,
            tls=tls,
        )
        connection_app = Connection(
            server,
            LDAP_APP_DN,
            LDAP_APP_PASSWORD,
            auto_bind="NONE",
            authentication="SIMPLE" if LDAP_APP_DN else "ANONYMOUS",
        )
        if not connection_app.bind():
            raise HTTPException(400, detail="Application account bind failed")

        search_success = connection_app.search(
            search_base=LDAP_SEARCH_BASE,
            search_filter=f"(&({LDAP_ATTRIBUTE_FOR_USERNAME}={escape_filter_chars(form_data.user.lower())}){LDAP_SEARCH_FILTERS})",
            attributes=[
                f"{LDAP_ATTRIBUTE_FOR_USERNAME}",
                f"{LDAP_ATTRIBUTE_FOR_MAIL}",
                "cn",
            ],
        )

        if not search_success or not connection_app.entries:
            raise HTTPException(400, detail="User not found in the LDAP server")

        entry = connection_app.entries[0]
        username = str(entry[f"{LDAP_ATTRIBUTE_FOR_USERNAME}"]).lower()
        email = entry[
            f"{LDAP_ATTRIBUTE_FOR_MAIL}"
        ].value  # retrieve the Attribute value
        if not email:
            raise HTTPException(400, "User does not have a valid email address.")
        elif isinstance(email, str):
            email = email.lower()
        elif isinstance(email, list):
            email = email[0].lower()
        else:
            email = str(email).lower()

        cn = str(entry["cn"])
        user_dn = entry.entry_dn

        if username == form_data.user.lower():
            connection_user = Connection(
                server,
                user_dn,
                form_data.password,
                auto_bind="NONE",
                authentication="SIMPLE",
            )
            if not connection_user.bind():
                raise HTTPException(400, "Authentication failed.")

            user = Users.get_user_by_email(email)
            if not user:
                try:
                    user_count = Users.get_num_users()

                    role = (
                        "admin"
                        if user_count == 0
                        else request.app.state.config.DEFAULT_USER_ROLE
                    )

                    user = Auths.insert_new_auth(
                        email=email,
                        password=str(uuid.uuid4()),
                        name=cn,
                        role=role,
                    )

                    if not user:
                        raise HTTPException(
                            500, detail=ERROR_MESSAGES.CREATE_USER_ERROR
                        )

                except HTTPException:
                    raise
                except Exception as err:
                    log.error(f"LDAP user creation error: {str(err)}")
                    raise HTTPException(
                        500, detail="Internal error occurred during LDAP user creation."
                    )

            user = Auths.authenticate_user_by_trusted_header(email)

            if user:
                expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
                expires_at = None
                if expires_delta:
                    expires_at = int(time.time()) + int(expires_delta.total_seconds())

                token = create_token(
                    data={"id": user.id},
                    expires_delta=expires_delta,
                )

                # Set the cookie token
                response.set_cookie(
                    key="token",
                    value=token,
                    expires=(
                        datetime.datetime.fromtimestamp(
                            expires_at, datetime.timezone.utc
                        )
                        if expires_at
                        else None
                    ),
                    httponly=True,  # Ensures the cookie is not accessible via JavaScript
                    samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
                    secure=WEBUI_AUTH_COOKIE_SECURE,
                )

                user_permissions = get_permissions(
                    user.id, request.app.state.config.USER_PERMISSIONS
                )

                credit = Credits.init_credit_by_user_id(user.id)

                return {
                    "token": token,
                    "token_type": "Bearer",
                    "expires_at": expires_at,
                    "id": user.id,
                    "email": user.email,
                    "name": user.name,
                    "role": user.role,
                    "profile_image_url": user.profile_image_url,
                    "permissions": user_permissions,
                    "credit": credit.credit,
                }
            else:
                raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)
        else:
            raise HTTPException(400, "User record mismatch.")
    except Exception as e:
        log.error(f"LDAP authentication error: {str(e)}")
        raise HTTPException(400, detail="LDAP authentication failed.")


############################
# SignIn
############################


@router.post("/signin", response_model=SessionUserResponse)
async def signin(request: Request, response: Response, form_data: SigninForm):
    if WEBUI_AUTH_TRUSTED_EMAIL_HEADER:
        if WEBUI_AUTH_TRUSTED_EMAIL_HEADER not in request.headers:
            raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_TRUSTED_HEADER)

        trusted_email = request.headers[WEBUI_AUTH_TRUSTED_EMAIL_HEADER].lower()
        trusted_name = trusted_email
        if WEBUI_AUTH_TRUSTED_NAME_HEADER:
            trusted_name = request.headers.get(
                WEBUI_AUTH_TRUSTED_NAME_HEADER, trusted_email
            )
        if not Users.get_user_by_email(trusted_email.lower()):
            await signup(
                request,
                response,
                SignupForm(
                    email=trusted_email, password=str(uuid.uuid4()), name=trusted_name
                ),
            )
        user = Auths.authenticate_user_by_trusted_header(trusted_email)
    elif WEBUI_AUTH == False:
        admin_email = "admin@localhost"
        admin_password = "admin"

        if Users.get_user_by_email(admin_email.lower()):
            user = Auths.authenticate_user(admin_email.lower(), admin_password)
        else:
            if Users.get_num_users() != 0:
                raise HTTPException(400, detail=ERROR_MESSAGES.EXISTING_USERS)

            await signup(
                request,
                response,
                SignupForm(email=admin_email, password=admin_password, name="User"),
            )

            user = Auths.authenticate_user(admin_email.lower(), admin_password)
    else:
        user = Auths.authenticate_user(form_data.email.lower(), form_data.password)

    if user:

        expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
        expires_at = None
        if expires_delta:
            expires_at = int(time.time()) + int(expires_delta.total_seconds())

        token = create_token(
            data={"id": user.id},
            expires_delta=expires_delta,
        )

        datetime_expires_at = (
            datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
            if expires_at
            else None
        )

        # Set the cookie token
        response.set_cookie(
            key="token",
            value=token,
            expires=datetime_expires_at,
            httponly=True,  # Ensures the cookie is not accessible via JavaScript
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
        )

        user_permissions = get_permissions(
            user.id, request.app.state.config.USER_PERMISSIONS
        )

        credit = Credits.init_credit_by_user_id(user.id)

        return {
            "token": token,
            "token_type": "Bearer",
            "expires_at": expires_at,
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "profile_image_url": user.profile_image_url,
            "permissions": user_permissions,
            "credit": credit.credit,
        }
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)


############################
# SignUp
############################


@router.post("/signup", response_model=SessionUserResponse)
async def signup(request: Request, response: Response, form_data: SignupForm):
    if WEBUI_AUTH:
        if (
            not request.app.state.config.ENABLE_SIGNUP
            or not request.app.state.config.ENABLE_LOGIN_FORM
        ):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.ACCESS_PROHIBITED
            )
    else:
        if Users.get_num_users() != 0:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.ACCESS_PROHIBITED
            )

    # check for email domain whitelist
    email_domain_whitelist = [
        i.strip()
        for i in request.app.state.config.SIGNUP_EMAIL_DOMAIN_WHITELIST.split(",")
        if i
    ]
    if email_domain_whitelist:
        domain = form_data.email.split("@")[-1]
        if domain not in email_domain_whitelist:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"Only emails from {request.app.state.config.SIGNUP_EMAIL_DOMAIN_WHITELIST} are allowed",
            )

    user_count = Users.get_num_users()
    if not validate_email_format(form_data.email.lower()):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail=ERROR_MESSAGES.INVALID_EMAIL_FORMAT
        )

    if Users.get_user_by_email(form_data.email.lower()):
        raise HTTPException(400, detail=ERROR_MESSAGES.EMAIL_TAKEN)

    try:
        if user_count == 0:
            role = "admin"
        elif request.app.state.config.ENABLE_SIGNUP_VERIFY:
            role = "pending"
            send_verify_email(email=form_data.email.lower())
        else:
            role = request.app.state.config.DEFAULT_USER_ROLE

        if user_count == 0:
            # Disable signup after the first user is created
            request.app.state.config.ENABLE_SIGNUP = False

        # The password passed to bcrypt must be 72 bytes or fewer. If it is longer, it will be truncated before hashing.
        if len(form_data.password.encode("utf-8")) > 72:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.PASSWORD_TOO_LONG,
            )

        hashed = get_password_hash(form_data.password)
        user = Auths.insert_new_auth(
            form_data.email.lower(),
            hashed,
            form_data.name,
            form_data.profile_image_url,
            role,
        )

        if user:
            expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
            expires_at = None
            if expires_delta:
                expires_at = int(time.time()) + int(expires_delta.total_seconds())

            token = create_token(
                data={"id": user.id},
                expires_delta=expires_delta,
            )

            datetime_expires_at = (
                datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
                if expires_at
                else None
            )

            # Set the cookie token
            response.set_cookie(
                key="token",
                value=token,
                expires=datetime_expires_at,
                httponly=True,  # Ensures the cookie is not accessible via JavaScript
                samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
                secure=WEBUI_AUTH_COOKIE_SECURE,
            )

            if request.app.state.config.WEBHOOK_URL:
                post_webhook(
                    request.app.state.WEBUI_NAME,
                    request.app.state.config.WEBHOOK_URL,
                    WEBHOOK_MESSAGES.USER_SIGNUP(user.name),
                    {
                        "action": "signup",
                        "message": WEBHOOK_MESSAGES.USER_SIGNUP(user.name),
                        "user": user.model_dump_json(exclude_none=True),
                    },
                )

            user_permissions = get_permissions(
                user.id, request.app.state.config.USER_PERMISSIONS
            )

            credit = Credits.init_credit_by_user_id(user.id)

            return {
                "token": token,
                "token_type": "Bearer",
                "expires_at": expires_at,
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "profile_image_url": user.profile_image_url,
                "permissions": user_permissions,
                "credit": credit.credit,
            }
        else:
            raise HTTPException(500, detail=ERROR_MESSAGES.CREATE_USER_ERROR)
    except Exception as err:
        log.error(f"Signup error: {str(err)}")
        raise HTTPException(500, detail="An internal error occurred during signup.")


@router.get("/signup_verify/{code}")
async def signup_verify(request: Request, code: str):
    email = verify_email_by_code(code=code)
    if not email:
        raise HTTPException(403, detail="Invalid code")

    user = Users.get_user_by_email(email)
    if not user:
        raise HTTPException(404, detail="User not found")

    Users.update_user_role_by_id(user.id, "user")
    return RedirectResponse(url=request.app.state.config.WEBUI_URL)


@router.get("/signout")
async def signout(request: Request, response: Response):
    response.delete_cookie("token")

    if ENABLE_OAUTH_SIGNUP.value:
        oauth_id_token = request.cookies.get("oauth_id_token")
        if oauth_id_token:
            try:
                async with ClientSession() as session:
                    async with session.get(OPENID_PROVIDER_URL.value) as resp:
                        if resp.status == 200:
                            openid_data = await resp.json()
                            logout_url = openid_data.get("end_session_endpoint")
                            if logout_url:
                                response.delete_cookie("oauth_id_token")
                                return RedirectResponse(
                                    headers=response.headers,
                                    url=f"{logout_url}?id_token_hint={oauth_id_token}",
                                )
                        else:
                            raise HTTPException(
                                status_code=resp.status,
                                detail="Failed to fetch OpenID configuration",
                            )
            except Exception as e:
                log.error(f"OpenID signout error: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail="Failed to sign out from the OpenID provider.",
                )

    if WEBUI_AUTH_SIGNOUT_REDIRECT_URL:
        return RedirectResponse(
            headers=response.headers,
            url=WEBUI_AUTH_SIGNOUT_REDIRECT_URL,
        )

    return {"status": True}


############################
# AddUser
############################


@router.post("/add", response_model=SigninResponse)
async def add_user(form_data: AddUserForm, user=Depends(get_admin_user)):
    if not validate_email_format(form_data.email.lower()):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail=ERROR_MESSAGES.INVALID_EMAIL_FORMAT
        )

    if Users.get_user_by_email(form_data.email.lower()):
        raise HTTPException(400, detail=ERROR_MESSAGES.EMAIL_TAKEN)

    try:
        hashed = get_password_hash(form_data.password)
        user = Auths.insert_new_auth(
            form_data.email.lower(),
            hashed,
            form_data.name,
            form_data.profile_image_url,
            form_data.role,
        )

        if user:
            token = create_token(data={"id": user.id})
            return {
                "token": token,
                "token_type": "Bearer",
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "profile_image_url": user.profile_image_url,
            }
        else:
            raise HTTPException(500, detail=ERROR_MESSAGES.CREATE_USER_ERROR)
    except Exception as err:
        log.error(f"Add user error: {str(err)}")
        raise HTTPException(
            500, detail="An internal error occurred while adding the user."
        )


############################
# GetAdminDetails
############################


@router.get("/admin/details")
async def get_admin_details(request: Request, user=Depends(get_current_user)):
    if request.app.state.config.SHOW_ADMIN_DETAILS:
        admin_email = request.app.state.config.ADMIN_EMAIL
        admin_name = None

        log.info(f"Admin details - Email: {admin_email}, Name: {admin_name}")

        if admin_email:
            admin = Users.get_user_by_email(admin_email)
            if admin:
                admin_name = admin.name
        else:
            admin = Users.get_first_user()
            if admin:
                admin_email = admin.email
                admin_name = admin.name

        return {
            "name": admin_name,
            "email": admin_email,
        }
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.ACTION_PROHIBITED)


############################
# ToggleSignUp
############################


@router.get("/admin/config")
async def get_admin_config(request: Request, user=Depends(get_admin_user)):
    return {
        "SHOW_ADMIN_DETAILS": request.app.state.config.SHOW_ADMIN_DETAILS,
        "WEBUI_URL": request.app.state.config.WEBUI_URL,
        "ENABLE_SIGNUP": request.app.state.config.ENABLE_SIGNUP,
        "ENABLE_SIGNUP_VERIFY": request.app.state.config.ENABLE_SIGNUP_VERIFY,
        "SIGNUP_EMAIL_DOMAIN_WHITELIST": request.app.state.config.SIGNUP_EMAIL_DOMAIN_WHITELIST,
        "ENABLE_API_KEY": request.app.state.config.ENABLE_API_KEY,
        "ENABLE_API_KEY_ENDPOINT_RESTRICTIONS": request.app.state.config.ENABLE_API_KEY_ENDPOINT_RESTRICTIONS,
        "API_KEY_ALLOWED_ENDPOINTS": request.app.state.config.API_KEY_ALLOWED_ENDPOINTS,
        "DEFAULT_USER_ROLE": request.app.state.config.DEFAULT_USER_ROLE,
        "JWT_EXPIRES_IN": request.app.state.config.JWT_EXPIRES_IN,
        "ENABLE_COMMUNITY_SHARING": request.app.state.config.ENABLE_COMMUNITY_SHARING,
        "ENABLE_MESSAGE_RATING": request.app.state.config.ENABLE_MESSAGE_RATING,
        "ENABLE_CHANNELS": request.app.state.config.ENABLE_CHANNELS,
        "ENABLE_NOTES": request.app.state.config.ENABLE_NOTES,
        "ENABLE_USER_WEBHOOKS": request.app.state.config.ENABLE_USER_WEBHOOKS,
        # 添加SMTP配置
        "SMTP_HOST": request.app.state.config.SMTP_HOST,
        "SMTP_PORT": request.app.state.config.SMTP_PORT,
        "SMTP_USERNAME": request.app.state.config.SMTP_USERNAME,
        "SMTP_PASSWORD": request.app.state.config.SMTP_PASSWORD,
        # 组织名称，填写你喜欢的名称
        "ORGANIZATION_NAME": request.app.state.config.ORGANIZATION_NAME,
        # 网站名称
        "CUSTOM_NAME": request.app.state.config.CUSTOM_NAME,
        # 网站 Logo，ICO 格式
        "CUSTOM_ICO": request.app.state.config.CUSTOM_ICO,
        # 网站 Logo，PNG 格式
        "CUSTOM_PNG": request.app.state.config.CUSTOM_PNG,
        # 网站 Logo，SVG 格式
        "CUSTOM_SVG": request.app.state.config.CUSTOM_SVG,
        # 网站深色模式 LOGO，PNG 格式
        "CUSTOM_DARK_PNG": request.app.state.config.CUSTOM_DARK_PNG,
        # 添加短信服务配置
        "SMS_ACCESS_KEY_ID": request.app.state.config.SMS_ACCESS_KEY_ID,
        "SMS_ACCESS_KEY_SECRET": request.app.state.config.SMS_ACCESS_KEY_SECRET,
        "SMS_SIGN_NAME": request.app.state.config.SMS_SIGN_NAME,
        "SMS_TEMPLATE_CODE": request.app.state.config.SMS_TEMPLATE_CODE,
        "SMS_ENDPOINT": request.app.state.config.SMS_ENDPOINT,
        # 添加微信登录配置
        "ENABLE_WECHAT_LOGIN": request.app.state.config.ENABLE_WECHAT_LOGIN,
        "WECHAT_APP_ID": request.app.state.config.WECHAT_APP_ID,
        "WECHAT_APP_SECRET": request.app.state.config.WECHAT_APP_SECRET,
        "WECHAT_REDIRECT_URI": request.app.state.config.WECHAT_REDIRECT_URI,
        "WECHAT_TOKEN": request.app.state.config.WECHAT_TOKEN,
        "WECHAT_AES_KEY": request.app.state.config.WECHAT_AES_KEY,
        # 添加微信消息推送配置
        "WECHAT_WELCOME_ENABLED": request.app.state.config.WECHAT_WELCOME_ENABLED,
        "WECHAT_WELCOME_MESSAGE": request.app.state.config.WECHAT_WELCOME_MESSAGE,
        "WECHAT_AUTO_REPLY_ENABLED": request.app.state.config.WECHAT_AUTO_REPLY_ENABLED,
        "WECHAT_DEFAULT_REPLY_MESSAGE": request.app.state.config.WECHAT_DEFAULT_REPLY_MESSAGE,
        "WECHAT_KEYWORD_REPLIES": request.app.state.config.WECHAT_KEYWORD_REPLIES,
    }


class AdminConfig(BaseModel):
    SHOW_ADMIN_DETAILS: bool
    WEBUI_URL: str
    ENABLE_SIGNUP: bool
    ENABLE_SIGNUP_VERIFY: bool = Field(default=False)
    SIGNUP_EMAIL_DOMAIN_WHITELIST: str = Field(default="")
    ENABLE_API_KEY: bool
    ENABLE_API_KEY_ENDPOINT_RESTRICTIONS: bool
    API_KEY_ALLOWED_ENDPOINTS: str
    DEFAULT_USER_ROLE: str
    JWT_EXPIRES_IN: str
    ENABLE_COMMUNITY_SHARING: bool
    ENABLE_MESSAGE_RATING: bool
    ENABLE_CHANNELS: bool
    ENABLE_NOTES: bool
    ENABLE_USER_WEBHOOKS: bool
    # 添加SMTP配置
    SMTP_HOST: str
    SMTP_PORT: int
    SMTP_USERNAME: str
    SMTP_PASSWORD: str
    # 组织名称，填写你喜欢的名称
    ORGANIZATION_NAME: str
    # 网站名称
    CUSTOM_NAME: str
    # 网站 Logo，ICO 格式
    CUSTOM_ICO: str
    # 网站 Logo，PNG 格式
    CUSTOM_PNG: str
    # 网站 Logo，SVG 格式
    CUSTOM_SVG: str
    # 网站深色模式 LOGO，PNG 格式
    CUSTOM_DARK_PNG: str
    # 添加短信服务配置
    SMS_ACCESS_KEY_ID: str = Field(default="")
    SMS_ACCESS_KEY_SECRET: str = Field(default="")
    SMS_SIGN_NAME: str = Field(default="")
    SMS_TEMPLATE_CODE: str = Field(default="")
    SMS_ENDPOINT: str = Field(default="dysmsapi.aliyuncs.com")
    # 添加微信登录配置
    ENABLE_WECHAT_LOGIN: bool = Field(default=False)
    WECHAT_APP_ID: str = Field(default="")
    WECHAT_APP_SECRET: str = Field(default="")
    WECHAT_REDIRECT_URI: str = Field(default="")
    WECHAT_TOKEN: str = Field(default="")
    WECHAT_AES_KEY: str = Field(default="")
    # 添加微信消息推送配置
    WECHAT_WELCOME_ENABLED: bool = Field(default=True)
    WECHAT_WELCOME_MESSAGE: str = Field(
        default="欢迎关注！\n\n您已成功关注我们的公众号，现在可以使用微信快速登录我们的AI平台了！\n\n 功能特色：\n• 微信快捷登录\n• 智能AI对话\n• 多模型支持\n\n点击菜单或发送消息开始体验吧！"
    )
    WECHAT_AUTO_REPLY_ENABLED: bool = Field(default=True)
    WECHAT_DEFAULT_REPLY_MESSAGE: str = Field(
        default="您好！\n\n感谢您的消息。如需使用完整AI功能，请访问我们的网站进行体验。\n\n网站地址：{WEBUI_URL}\n\n您也可以点击菜单中的「AI对话」直接开始体验！"
    )
    WECHAT_KEYWORD_REPLIES: List[dict] = Field(default=[])


@router.post("/admin/config")
async def update_admin_config(
    request: Request, form_data: AdminConfig, user=Depends(get_admin_user)
):
    request.app.state.config.SHOW_ADMIN_DETAILS = form_data.SHOW_ADMIN_DETAILS
    request.app.state.config.WEBUI_URL = form_data.WEBUI_URL
    request.app.state.config.ENABLE_SIGNUP = form_data.ENABLE_SIGNUP
    request.app.state.config.ENABLE_SIGNUP_VERIFY = form_data.ENABLE_SIGNUP_VERIFY
    request.app.state.config.SIGNUP_EMAIL_DOMAIN_WHITELIST = (
        form_data.SIGNUP_EMAIL_DOMAIN_WHITELIST
    )

    request.app.state.config.ENABLE_API_KEY = form_data.ENABLE_API_KEY
    request.app.state.config.ENABLE_API_KEY_ENDPOINT_RESTRICTIONS = (
        form_data.ENABLE_API_KEY_ENDPOINT_RESTRICTIONS
    )
    request.app.state.config.API_KEY_ALLOWED_ENDPOINTS = (
        form_data.API_KEY_ALLOWED_ENDPOINTS
    )

    request.app.state.config.ENABLE_CHANNELS = form_data.ENABLE_CHANNELS
    request.app.state.config.ENABLE_NOTES = form_data.ENABLE_NOTES

    if form_data.DEFAULT_USER_ROLE in ["pending", "user", "admin"]:
        request.app.state.config.DEFAULT_USER_ROLE = form_data.DEFAULT_USER_ROLE

    pattern = r"^(-1|0|(-?\d+(\.\d+)?)(ms|s|m|h|d|w))$"

    # Check if the input string matches the pattern
    if re.match(pattern, form_data.JWT_EXPIRES_IN):
        request.app.state.config.JWT_EXPIRES_IN = form_data.JWT_EXPIRES_IN

    request.app.state.config.ENABLE_COMMUNITY_SHARING = (
        form_data.ENABLE_COMMUNITY_SHARING
    )
    request.app.state.config.ENABLE_MESSAGE_RATING = form_data.ENABLE_MESSAGE_RATING

    request.app.state.config.ENABLE_USER_WEBHOOKS = form_data.ENABLE_USER_WEBHOOKS
    # 添加SMTP配置
    request.app.state.config.SMTP_HOST = form_data.SMTP_HOST
    request.app.state.config.SMTP_PORT = form_data.SMTP_PORT
    request.app.state.config.SMTP_USERNAME = form_data.SMTP_USERNAME
    request.app.state.config.SMTP_PASSWORD = form_data.SMTP_PASSWORD
    # 组织名称，填写你喜欢的名称
    request.app.state.config.ORGANIZATION_NAME = form_data.ORGANIZATION_NAME
    # 网站名称
    request.app.state.config.CUSTOM_NAME = form_data.CUSTOM_NAME
    # 网站 Logo，ICO 格式
    request.app.state.config.CUSTOM_ICO = form_data.CUSTOM_ICO
    # 网站 Logo，PNG 格式
    request.app.state.config.CUSTOM_PNG = form_data.CUSTOM_PNG
    # 网站 Logo，SVG 格式
    request.app.state.config.CUSTOM_SVG = form_data.CUSTOM_SVG
    # 网站深色模式 LOGO，PNG 格式
    request.app.state.config.CUSTOM_DARK_PNG = form_data.CUSTOM_DARK_PNG
    # 添加短信服务配置
    request.app.state.config.SMS_ACCESS_KEY_ID = form_data.SMS_ACCESS_KEY_ID
    request.app.state.config.SMS_ACCESS_KEY_SECRET = form_data.SMS_ACCESS_KEY_SECRET
    request.app.state.config.SMS_SIGN_NAME = form_data.SMS_SIGN_NAME
    request.app.state.config.SMS_TEMPLATE_CODE = form_data.SMS_TEMPLATE_CODE
    request.app.state.config.SMS_ENDPOINT = form_data.SMS_ENDPOINT
    # 添加微信登录配置
    request.app.state.config.ENABLE_WECHAT_LOGIN = form_data.ENABLE_WECHAT_LOGIN
    request.app.state.config.WECHAT_APP_ID = form_data.WECHAT_APP_ID
    request.app.state.config.WECHAT_APP_SECRET = form_data.WECHAT_APP_SECRET
    request.app.state.config.WECHAT_REDIRECT_URI = form_data.WECHAT_REDIRECT_URI
    request.app.state.config.WECHAT_TOKEN = form_data.WECHAT_TOKEN
    request.app.state.config.WECHAT_AES_KEY = form_data.WECHAT_AES_KEY
    # 添加微信消息推送配置
    request.app.state.config.WECHAT_WELCOME_ENABLED = form_data.WECHAT_WELCOME_ENABLED
    request.app.state.config.WECHAT_WELCOME_MESSAGE = form_data.WECHAT_WELCOME_MESSAGE
    request.app.state.config.WECHAT_AUTO_REPLY_ENABLED = (
        form_data.WECHAT_AUTO_REPLY_ENABLED
    )
    request.app.state.config.WECHAT_DEFAULT_REPLY_MESSAGE = (
        form_data.WECHAT_DEFAULT_REPLY_MESSAGE
    )
    request.app.state.config.WECHAT_KEYWORD_REPLIES = form_data.WECHAT_KEYWORD_REPLIES

    get_license_data(
        request.app,
        "",
        form_data.CUSTOM_PNG,
        form_data.CUSTOM_SVG,
        form_data.CUSTOM_ICO,
        form_data.CUSTOM_DARK_PNG,
        form_data.ORGANIZATION_NAME,
    )
    return {
        "SHOW_ADMIN_DETAILS": request.app.state.config.SHOW_ADMIN_DETAILS,
        "WEBUI_URL": request.app.state.config.WEBUI_URL,
        "ENABLE_SIGNUP": request.app.state.config.ENABLE_SIGNUP,
        "ENABLE_SIGNUP_VERIFY": request.app.state.config.ENABLE_SIGNUP_VERIFY,
        "SIGNUP_EMAIL_DOMAIN_WHITELIST": request.app.state.config.SIGNUP_EMAIL_DOMAIN_WHITELIST,
        "ENABLE_API_KEY": request.app.state.config.ENABLE_API_KEY,
        "ENABLE_API_KEY_ENDPOINT_RESTRICTIONS": request.app.state.config.ENABLE_API_KEY_ENDPOINT_RESTRICTIONS,
        "API_KEY_ALLOWED_ENDPOINTS": request.app.state.config.API_KEY_ALLOWED_ENDPOINTS,
        "DEFAULT_USER_ROLE": request.app.state.config.DEFAULT_USER_ROLE,
        "JWT_EXPIRES_IN": request.app.state.config.JWT_EXPIRES_IN,
        "ENABLE_COMMUNITY_SHARING": request.app.state.config.ENABLE_COMMUNITY_SHARING,
        "ENABLE_MESSAGE_RATING": request.app.state.config.ENABLE_MESSAGE_RATING,
        "ENABLE_CHANNELS": request.app.state.config.ENABLE_CHANNELS,
        "ENABLE_NOTES": request.app.state.config.ENABLE_NOTES,
        "ENABLE_USER_WEBHOOKS": request.app.state.config.ENABLE_USER_WEBHOOKS,
        # 添加SMTP配置
        "SMTP_HOST": request.app.state.config.SMTP_HOST,
        "SMTP_PORT": request.app.state.config.SMTP_PORT,
        "SMTP_USERNAME": request.app.state.config.SMTP_USERNAME,
        "SMTP_PASSWORD": request.app.state.config.SMTP_PASSWORD,
        # 组织名称，填写你喜欢的名称
        "ORGANIZATION_NAME": request.app.state.config.ORGANIZATION_NAME,
        # 网站名称
        "CUSTOM_NAME": request.app.state.config.CUSTOM_NAME,
        # 网站 Logo，ICO 格式
        "CUSTOM_ICO": request.app.state.config.CUSTOM_ICO,
        # 网站 Logo，PNG 格式
        "CUSTOM_PNG": request.app.state.config.CUSTOM_PNG,
        # 网站 Logo，SVG 格式
        "CUSTOM_SVG": request.app.state.config.CUSTOM_SVG,
        # 网站深色模式 LOGO，PNG 格式
        "CUSTOM_DARK_PNG": request.app.state.config.CUSTOM_DARK_PNG,
        # 添加短信服务配置
        "SMS_ACCESS_KEY_ID": request.app.state.config.SMS_ACCESS_KEY_ID,
        "SMS_ACCESS_KEY_SECRET": request.app.state.config.SMS_ACCESS_KEY_SECRET,
        "SMS_SIGN_NAME": request.app.state.config.SMS_SIGN_NAME,
        "SMS_TEMPLATE_CODE": request.app.state.config.SMS_TEMPLATE_CODE,
        "SMS_ENDPOINT": request.app.state.config.SMS_ENDPOINT,
        # 添加微信登录配置
        "ENABLE_WECHAT_LOGIN": request.app.state.config.ENABLE_WECHAT_LOGIN,
        "WECHAT_APP_ID": request.app.state.config.WECHAT_APP_ID,
        "WECHAT_APP_SECRET": request.app.state.config.WECHAT_APP_SECRET,
        "WECHAT_REDIRECT_URI": request.app.state.config.WECHAT_REDIRECT_URI,
        "WECHAT_TOKEN": request.app.state.config.WECHAT_TOKEN,
        "WECHAT_AES_KEY": request.app.state.config.WECHAT_AES_KEY,
        # 添加微信消息推送配置
        "WECHAT_WELCOME_ENABLED": request.app.state.config.WECHAT_WELCOME_ENABLED,
        "WECHAT_WELCOME_MESSAGE": request.app.state.config.WECHAT_WELCOME_MESSAGE,
        "WECHAT_AUTO_REPLY_ENABLED": request.app.state.config.WECHAT_AUTO_REPLY_ENABLED,
        "WECHAT_DEFAULT_REPLY_MESSAGE": request.app.state.config.WECHAT_DEFAULT_REPLY_MESSAGE,
        "WECHAT_KEYWORD_REPLIES": request.app.state.config.WECHAT_KEYWORD_REPLIES,
    }


class LdapServerConfig(BaseModel):
    label: str
    host: str
    port: Optional[int] = None
    attribute_for_mail: str = "mail"
    attribute_for_username: str = "uid"
    app_dn: str
    app_dn_password: str
    search_base: str
    search_filters: str = ""
    use_tls: bool = True
    certificate_path: Optional[str] = None
    ciphers: Optional[str] = "ALL"


@router.get("/admin/config/ldap/server", response_model=LdapServerConfig)
async def get_ldap_server(request: Request, user=Depends(get_admin_user)):
    return {
        "label": request.app.state.config.LDAP_SERVER_LABEL,
        "host": request.app.state.config.LDAP_SERVER_HOST,
        "port": request.app.state.config.LDAP_SERVER_PORT,
        "attribute_for_mail": request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL,
        "attribute_for_username": request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME,
        "app_dn": request.app.state.config.LDAP_APP_DN,
        "app_dn_password": request.app.state.config.LDAP_APP_PASSWORD,
        "search_base": request.app.state.config.LDAP_SEARCH_BASE,
        "search_filters": request.app.state.config.LDAP_SEARCH_FILTERS,
        "use_tls": request.app.state.config.LDAP_USE_TLS,
        "certificate_path": request.app.state.config.LDAP_CA_CERT_FILE,
        "ciphers": request.app.state.config.LDAP_CIPHERS,
    }


@router.post("/admin/config/ldap/server")
async def update_ldap_server(
    request: Request, form_data: LdapServerConfig, user=Depends(get_admin_user)
):
    required_fields = [
        "label",
        "host",
        "attribute_for_mail",
        "attribute_for_username",
        "app_dn",
        "app_dn_password",
        "search_base",
    ]
    for key in required_fields:
        value = getattr(form_data, key)
        if not value:
            raise HTTPException(400, detail=f"Required field {key} is empty")

    request.app.state.config.LDAP_SERVER_LABEL = form_data.label
    request.app.state.config.LDAP_SERVER_HOST = form_data.host
    request.app.state.config.LDAP_SERVER_PORT = form_data.port
    request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL = form_data.attribute_for_mail
    request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME = (
        form_data.attribute_for_username
    )
    request.app.state.config.LDAP_APP_DN = form_data.app_dn
    request.app.state.config.LDAP_APP_PASSWORD = form_data.app_dn_password
    request.app.state.config.LDAP_SEARCH_BASE = form_data.search_base
    request.app.state.config.LDAP_SEARCH_FILTERS = form_data.search_filters
    request.app.state.config.LDAP_USE_TLS = form_data.use_tls
    request.app.state.config.LDAP_CA_CERT_FILE = form_data.certificate_path
    request.app.state.config.LDAP_CIPHERS = form_data.ciphers

    return {
        "label": request.app.state.config.LDAP_SERVER_LABEL,
        "host": request.app.state.config.LDAP_SERVER_HOST,
        "port": request.app.state.config.LDAP_SERVER_PORT,
        "attribute_for_mail": request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL,
        "attribute_for_username": request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME,
        "app_dn": request.app.state.config.LDAP_APP_DN,
        "app_dn_password": request.app.state.config.LDAP_APP_PASSWORD,
        "search_base": request.app.state.config.LDAP_SEARCH_BASE,
        "search_filters": request.app.state.config.LDAP_SEARCH_FILTERS,
        "use_tls": request.app.state.config.LDAP_USE_TLS,
        "certificate_path": request.app.state.config.LDAP_CA_CERT_FILE,
        "ciphers": request.app.state.config.LDAP_CIPHERS,
    }


@router.get("/admin/config/ldap")
async def get_ldap_config(request: Request, user=Depends(get_admin_user)):
    return {"ENABLE_LDAP": request.app.state.config.ENABLE_LDAP}


class LdapConfigForm(BaseModel):
    enable_ldap: Optional[bool] = None


@router.post("/admin/config/ldap")
async def update_ldap_config(
    request: Request, form_data: LdapConfigForm, user=Depends(get_admin_user)
):
    request.app.state.config.ENABLE_LDAP = form_data.enable_ldap
    return {"ENABLE_LDAP": request.app.state.config.ENABLE_LDAP}


############################
# API Key
############################


# create api key
@router.post("/api_key", response_model=ApiKey)
async def generate_api_key(request: Request, user=Depends(get_current_user)):
    if not request.app.state.config.ENABLE_API_KEY:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.API_KEY_CREATION_NOT_ALLOWED,
        )

    api_key = create_api_key()
    success = Users.update_user_api_key_by_id(user.id, api_key)

    if success:
        return {
            "api_key": api_key,
        }
    else:
        raise HTTPException(500, detail=ERROR_MESSAGES.CREATE_API_KEY_ERROR)


# delete api key
@router.delete("/api_key", response_model=bool)
async def delete_api_key(user=Depends(get_current_user)):
    success = Users.update_user_api_key_by_id(user.id, None)
    return success


# get api key
@router.get("/api_key", response_model=ApiKey)
async def get_api_key(user=Depends(get_current_user)):
    api_key = Users.get_user_api_key_by_id(user.id)
    if api_key:
        return {
            "api_key": api_key,
        }
    else:
        raise HTTPException(404, detail=ERROR_MESSAGES.API_KEY_NOT_FOUND)


############################
# Debug SMS Configuration
############################


@router.get("/sms/debug/config")
async def debug_sms_config(request: Request, user=Depends(get_admin_user)):
    """调试短信配置信息（仅管理员）"""
    try:
        sms_config = SMSConfig(request)

        config_status = {
            "SMS_AVAILABLE": SMS_AVAILABLE,
            "configuration": {
                "ACCESS_KEY_ID": {
                    "configured": bool(sms_config.ACCESS_KEY_ID),
                    "value": (
                        f"{sms_config.ACCESS_KEY_ID[:8]}***"
                        if sms_config.ACCESS_KEY_ID
                        else ""
                    ),
                    "length": (
                        len(sms_config.ACCESS_KEY_ID) if sms_config.ACCESS_KEY_ID else 0
                    ),
                },
                "ACCESS_KEY_SECRET": {
                    "configured": bool(sms_config.ACCESS_KEY_SECRET),
                    "value": (
                        f"{sms_config.ACCESS_KEY_SECRET[:8]}***"
                        if sms_config.ACCESS_KEY_SECRET
                        else ""
                    ),
                    "length": (
                        len(sms_config.ACCESS_KEY_SECRET)
                        if sms_config.ACCESS_KEY_SECRET
                        else 0
                    ),
                },
                "SIGN_NAME": {
                    "configured": bool(sms_config.SIGN_NAME),
                    "value": sms_config.SIGN_NAME,
                },
                "TEMPLATE_CODE": {
                    "configured": bool(sms_config.TEMPLATE_CODE),
                    "value": sms_config.TEMPLATE_CODE,
                },
                "ENDPOINT": {
                    "configured": bool(sms_config.ENDPOINT),
                    "value": sms_config.ENDPOINT,
                },
            },
            "client_status": None,
            "errors": [],
        }

        # 检查配置完整性
        missing_configs = []
        if not sms_config.ACCESS_KEY_ID:
            missing_configs.append("ACCESS_KEY_ID")
        if not sms_config.ACCESS_KEY_SECRET:
            missing_configs.append("ACCESS_KEY_SECRET")
        if not sms_config.SIGN_NAME:
            missing_configs.append("SIGN_NAME")
        if not sms_config.TEMPLATE_CODE:
            missing_configs.append("TEMPLATE_CODE")

        if missing_configs:
            config_status["errors"].append(
                f"缺少必要配置: {', '.join(missing_configs)}"
            )

        # 尝试创建客户端
        try:
            client = SMSService.create_client(request)
            if client:
                config_status["client_status"] = "创建成功"
            else:
                config_status["client_status"] = "创建失败"
                config_status["errors"].append("短信客户端创建失败")
        except Exception as e:
            config_status["client_status"] = f"创建异常: {str(e)}"
            config_status["errors"].append(f"客户端异常: {str(e)}")

        # 检查SDK是否安装
        if not SMS_AVAILABLE:
            config_status["errors"].append(
                "阿里云短信SDK未安装，请运行: pip install alibabacloud_dysmsapi20170525"
            )

        return {
            "status": "success" if not config_status["errors"] else "error",
            "data": config_status,
        }
    except Exception as e:
        log.error(f"调试短信配置失败: {str(e)}")
        return {"status": "error", "message": str(e), "data": None}


@router.post("/sms/debug/test")
async def test_sms_send(request: Request, user=Depends(get_admin_user)):
    """测试短信发送功能（仅管理员，发送到固定测试号码）"""
    try:
        # 使用一个虚拟的测试手机号进行配置测试（不会真正发送）
        test_phone = "13800138000"
        test_code = "123456"

        log.info("=== 开始短信发送测试 ===")

        # 检查SDK可用性
        if not SMS_AVAILABLE:
            return {
                "status": "error",
                "message": "阿里云短信SDK未安装",
                "details": "请运行: pip install alibabacloud_dysmsapi20170525",
            }

        # 检查配置
        sms_config = SMSConfig(request)
        config_errors = []

        if not sms_config.ACCESS_KEY_ID:
            config_errors.append("ACCESS_KEY_ID未配置")
        if not sms_config.ACCESS_KEY_SECRET:
            config_errors.append("ACCESS_KEY_SECRET未配置")
        if not sms_config.SIGN_NAME:
            config_errors.append("SIGN_NAME未配置")
        if not sms_config.TEMPLATE_CODE:
            config_errors.append("TEMPLATE_CODE未配置")

        if config_errors:
            return {
                "status": "error",
                "message": "短信配置不完整",
                "details": config_errors,
            }

        # 尝试创建客户端
        try:
            client = SMSService.create_client(request)
            if not client:
                return {
                    "status": "error",
                    "message": "短信客户端创建失败",
                    "details": "请检查ACCESS_KEY_ID和ACCESS_KEY_SECRET是否正确",
                }
        except Exception as e:
            return {
                "status": "error",
                "message": "短信客户端创建异常",
                "details": str(e),
            }

        # 创建测试请求（但不实际发送）
        try:
            sms_request = dysmsapi_models.SendSmsRequest(
                phone_numbers=test_phone,
                sign_name=sms_config.SIGN_NAME,
                template_code=sms_config.TEMPLATE_CODE,
                template_param=json.dumps({"code": test_code}),
            )

            log.info("短信请求对象创建成功")

            return {
                "status": "success",
                "message": "短信配置测试通过",
                "details": {
                    "sdk_available": True,
                    "client_created": True,
                    "request_created": True,
                    "config_complete": True,
                    "note": "实际发送功能正常，此测试未真正发送短信",
                },
            }

        except Exception as e:
            return {"status": "error", "message": "短信请求创建失败", "details": str(e)}

    except Exception as e:
        log.error(f"短信发送测试失败: {str(e)}")
        return {"status": "error", "message": "测试过程异常", "details": str(e)}


############################
# 调试用户绑定状态接口
############################


@router.get("/debug/binding-status/{user_id}")
async def debug_user_binding_status(user_id: str, admin_user=Depends(get_admin_user)):
    """调试用户绑定状态（仅管理员）"""
    try:
        # 获取用户信息
        user = Users.get_user_by_id(user_id)
        if not user:
            return {"error": "用户不存在"}

        # 获取Auth表信息
        auth_by_email = Auths.get_auth_by_email(user.email) if user.email else None
        auth_by_phone = (
            Auths.get_auth_by_phone_number(user.phone_number)
            if user.phone_number
            else None
        )
        auth_by_wechat = (
            Auths.get_auth_by_wechat_openid(user.wechat_openid)
            if user.wechat_openid
            else None
        )

        return {
            "user_info": {
                "id": user.id,
                "email": user.email,
                "phone_number": user.phone_number,
                "wechat_openid": user.wechat_openid,
                "wechat_nickname": user.wechat_nickname,
                "primary_login_type": user.primary_login_type,
                "available_login_types": user.available_login_types,
                "binding_status": user.binding_status,
            },
            "auth_table_info": {
                "auth_by_email": (
                    {
                        "exists": bool(auth_by_email),
                        "phone_number": (
                            auth_by_email.phone_number if auth_by_email else None
                        ),
                        "wechat_openid": (
                            auth_by_email.wechat_openid if auth_by_email else None
                        ),
                    }
                    if auth_by_email
                    else None
                ),
                "auth_by_phone": (
                    {
                        "exists": bool(auth_by_phone),
                        "email": auth_by_phone.email if auth_by_phone else None,
                        "wechat_openid": (
                            auth_by_phone.wechat_openid if auth_by_phone else None
                        ),
                    }
                    if auth_by_phone
                    else None
                ),
                "auth_by_wechat": (
                    {
                        "exists": bool(auth_by_wechat),
                        "email": auth_by_wechat.email if auth_by_wechat else None,
                        "phone_number": (
                            auth_by_wechat.phone_number if auth_by_wechat else None
                        ),
                    }
                    if auth_by_wechat
                    else None
                ),
            },
            "binding_analysis": {
                "phone_properly_bound": bool(
                    user.phone_number and user.phone_number.strip()
                ),
                "wechat_properly_bound": bool(
                    user.wechat_openid and user.wechat_openid.strip()
                ),
                "auth_table_sync": {
                    "phone_in_auth": (
                        bool(auth_by_email and auth_by_email.phone_number)
                        if auth_by_email
                        else False
                    ),
                    "wechat_in_auth": (
                        bool(auth_by_email and auth_by_email.wechat_openid)
                        if auth_by_email
                        else False
                    ),
                },
            },
        }
    except Exception as e:
        return {"error": f"调试失败: {str(e)}"}


############################
# 微信用户绑定手机号接口
############################


class WeChatBindPhoneForm(BaseModel):
    openid: str = Field(..., description="微信openid")
    scene_id: str = Field(..., description="场景值")
    phone_number: str = Field(..., description="手机号码")
    verification_code: str = Field(..., description="验证码")


@router.post("/wechat/bind-phone", response_model=SessionUserResponse)
async def wechat_bind_phone(
    request: Request, response: Response, form_data: WeChatBindPhoneForm
):
    """微信用户绑定手机号"""
    if not request.app.state.config.ENABLE_WECHAT_LOGIN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="微信登录服务未启用"
        )

    try:
        openid = form_data.openid.strip()
        scene_id = form_data.scene_id.strip()
        phone_number = form_data.phone_number.strip()
        verification_code = form_data.verification_code.strip()

        # 验证场景值
        if not WeChatFollowService.validate_scene_id(scene_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="无效的场景值或已过期"
            )

        # 验证手机号格式
        if not validate_phone_number(phone_number):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="手机号格式不正确"
            )

        # 验证验证码
        if not verify_code(phone_number, verification_code, "bind"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="验证码错误或已过期"
            )

        # 获取微信用户信息
        user_info = await WeChatFollowService.get_wechat_user_info(request, openid)

        # 检查微信是否已有账号
        wechat_user = Users.get_user_by_wechat_openid(openid)

        if not wechat_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="微信账号不存在，请先进行微信登录",
            )

        # 检查手机号是否已被其他用户使用
        phone_auth = Auths.get_auth_by_phone_number(phone_number)
        phone_user = Users.get_user_by_phone_number(phone_number)

        if (phone_auth and phone_auth.id != wechat_user.id) or (
            phone_user and phone_user.id != wechat_user.id
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="该手机号已被其他用户使用",
            )

        # 直接为微信用户绑定手机号
        log.info(
            f"为微信用户绑定手机号: user_id={wechat_user.id}, phone_number={phone_number}"
        )

        # 更新用户的手机号信息
        Users.update_user_by_id(
            wechat_user.id,
            {
                "phone_number": phone_number,
            },
        )

        # 更新Auth表
        auth_update_success = Auths.update_auth_binding_info(
            user_id=wechat_user.id,
            login_type="phone",
            phone_number=phone_number,
        )

        if not auth_update_success:
            log.error(f"更新Auth表失败: user_id={wechat_user.id}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="绑定失败，无法更新认证信息",
            )

        # 重新获取用户信息，确保数据同步
        final_user = Users.get_user_by_id(wechat_user.id)
        log.info(
            f"绑定成功，用户信息: user_id={final_user.id}, phone_number={final_user.phone_number}"
        )

        # 确保获取到了有效的用户信息
        if not final_user:
            log.error("无法获取有效的用户信息")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="获取用户信息失败",
            )

        # 更新用户的可用登录方式和绑定状态
        log.info(f"更新用户登录方式和绑定状态: user_id={final_user.id}")

        # 确保登录方式包含手机号和微信
        current_login_types = getattr(
            final_user, "available_login_types", ""
        ) or getattr(final_user, "primary_login_type", "wechat")
        login_types_set = (
            set(current_login_types.split(",")) if current_login_types else set()
        )

        if final_user.phone_number:
            login_types_set.add("phone")
        if final_user.wechat_openid:
            login_types_set.add("wechat")
        if final_user.email and not final_user.email.endswith(
            ("@sms.local", "@wechat.local")
        ):
            login_types_set.add("email")

        Users.update_user_by_id(
            final_user.id,
            {
                "available_login_types": ",".join(sorted(login_types_set)),
                "binding_status": {
                    **getattr(final_user, "binding_status", {}),
                    "phone": "active" if final_user.phone_number else "inactive",
                    "wechat": "active" if final_user.wechat_openid else "inactive",
                },
            },
        )

        # 重新获取更新后的用户信息，确保数据同步
        final_user = Users.get_user_by_id(final_user.id)

        # 验证绑定是否成功（检查User表和Auth表）
        if not final_user.phone_number:
            log.error(f"绑定失败，用户表中仍然没有手机号: user_id={final_user.id}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="手机号绑定失败，请重试",
            )

        # 验证Auth表中的数据是否同步
        auth_record = Auths.get_auth_by_id(final_user.id)
        if not auth_record or not auth_record.phone_number:
            log.error(
                f"Auth表同步失败: user_id={final_user.id}, auth_phone={auth_record.phone_number if auth_record else 'None'}"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="认证信息同步失败，请重试",
            )

        log.info(
            f"绑定验证成功: user_id={final_user.id}, user_phone={final_user.phone_number}, auth_phone={auth_record.phone_number}"
        )

        # 生成JWT令牌
        expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
        expires_at = None
        if expires_delta:
            expires_at = int(time.time()) + int(expires_delta.total_seconds())

        token = create_token(
            data={"id": final_user.id},
            expires_delta=expires_delta,
        )

        datetime_expires_at = (
            datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
            if expires_at
            else None
        )

        # 设置Cookie
        response.set_cookie(
            key="token",
            value=token,
            expires=datetime_expires_at,
            httponly=True,
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
        )

        # 获取用户权限
        user_permissions = get_permissions(
            final_user.id, request.app.state.config.USER_PERMISSIONS
        )

        # 初始化用户积分
        credit = Credits.init_credit_by_user_id(final_user.id)

        # 清理场景值
        if scene_id in wechat_follow_states:
            del wechat_follow_states[scene_id]

        return {
            "token": token,
            "token_type": "Bearer",
            "expires_at": expires_at,
            "id": final_user.id,
            "email": final_user.email,
            "name": final_user.name,
            "role": final_user.role,
            "profile_image_url": final_user.profile_image_url,
            "permissions": user_permissions,
            "credit": credit.credit,
            "phone_number": final_user.phone_number,
            "wechat_openid": final_user.wechat_openid,
            "wechat_nickname": final_user.wechat_nickname,
            "primary_login_type": final_user.primary_login_type,
            "available_login_types": final_user.available_login_types,
            "binding_status": final_user.binding_status,
        }

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"微信绑定手机号失败: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"绑定失败: {str(e)}",
        )
