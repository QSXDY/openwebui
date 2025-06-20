import re
import uuid
import time
import datetime
import logging
import random
import json
from decimal import Decimal
import hashlib
import urllib.parse
import qrcode
from io import BytesIO
import base64

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

# 短信验证码存储（生产环境建议使用Redis）
sms_verification_codes = {}


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


# 短信服务类
class SMSService:
    @staticmethod
    def create_client(request: Request) -> Optional[DysmsapiClient]:
        """创建短信服务客户端"""
        if not SMS_AVAILABLE:
            return None

        try:
            sms_config = SMSConfig(request)
            config = open_api_models.Config(
                access_key_id=sms_config.ACCESS_KEY_ID,
                access_key_secret=sms_config.ACCESS_KEY_SECRET,
                endpoint=sms_config.ENDPOINT,
            )
            config.connect_timeout = 5000
            config.read_timeout = 10000
            return DysmsapiClient(config)
        except Exception as e:
            log.error(f"创建短信客户端失败: {str(e)}")
            return None

    @staticmethod
    def send_verification_sms(request: Request, phone_number: str, code: str) -> bool:
        """发送验证码短信"""
        if not SMS_AVAILABLE:
            log.error("短信SDK不可用")
            return False

        try:
            client = SMSService.create_client(request)
            if not client:
                return False

            sms_config = SMSConfig(request)
            request = dysmsapi_models.SendSmsRequest(
                phone_numbers=phone_number,
                sign_name=sms_config.SIGN_NAME,
                template_code=sms_config.TEMPLATE_CODE,
                template_param=json.dumps({"code": code}),
            )

            runtime = util_models.RuntimeOptions()
            runtime.autoretry = True
            runtime.max_attempts = 3

            response = client.send_sms_with_options(request, runtime)

            if response.body.code == "OK":
                log.info(f"短信发送成功，手机号: {phone_number}")
                return True
            else:
                log.error(f"短信发送失败: {response.body.message}")
                return False

        except Exception as e:
            log.error(f"发送短信异常: {str(e)}")
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

        # 获取access_token
        token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={app_id}&secret={app_secret}"

        async with ClientSession() as session:
            async with session.get(token_url) as response:
                token_data = await response.json()
                if "access_token" not in token_data:
                    raise ValueError(
                        f"获取access_token失败: {token_data.get('errmsg', '未知错误')}"
                    )

                access_token = token_data["access_token"]

            # 创建带参数二维码（临时二维码，10分钟过期）
            qr_url = f"https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token={access_token}"
            qr_data = {
                "expire_seconds": 600,  # 10分钟过期
                "action_name": "QR_STR_SCENE",
                "action_info": {"scene": {"scene_str": scene_id}},
            }

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

    @staticmethod
    async def get_wechat_user_info(request: Request, openid: str) -> dict:
        """获取微信用户信息"""
        app_id = request.app.state.config.WECHAT_APP_ID
        app_secret = request.app.state.config.WECHAT_APP_SECRET

        if not app_id or not app_secret:
            raise ValueError("微信公众号配置不完整")

        # 获取access_token
        token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={app_id}&secret={app_secret}"

        async with ClientSession() as session:
            async with session.get(token_url) as response:
                token_data = await response.json()
                if "access_token" not in token_data:
                    raise ValueError(
                        f"获取access_token失败: {token_data.get('errmsg', '未知错误')}"
                    )

                access_token = token_data["access_token"]

            # 获取用户信息
            user_url = f"https://api.weixin.qq.com/cgi-bin/user/info?access_token={access_token}&openid={openid}&lang=zh_CN"

            async with session.get(user_url) as response:
                user_data = await response.json()
                if "openid" not in user_data:
                    raise ValueError(
                        f"获取用户信息失败: {user_data.get('errmsg', '未知错误')}"
                    )

                return user_data

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

    # 如果是登录验证码，检查手机号是否已注册
    if form_data.type == "login":
        email = f"{phone_number}@sms.local"
        user = Users.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="该手机号尚未注册"
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


@router.post("/sms/register", response_model=SessionUserResponse)
async def sms_register(
    request: Request, response: Response, form_data: SMSRegisterForm
):
    """短信验证码注册"""
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

    # 检查手机号是否已注册
    email = f"{phone_number}@sms.local"
    if Users.get_user_by_email(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="该手机号已注册"
        )

    try:
        user_count = Users.get_num_users()
        role = (
            "admin" if user_count == 0 else request.app.state.config.DEFAULT_USER_ROLE
        )

        # 创建新用户
        hashed = get_password_hash(form_data.password)
        user = Auths.insert_new_auth(
            email=email,
            password=hashed,
            name=form_data.name,
            role=role,
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=ERROR_MESSAGES.CREATE_USER_ERROR,
            )

    except Exception as err:
        log.error(f"短信注册创建用户失败: {str(err)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="用户创建失败"
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
    email = f"{phone_number}@sms.local"
    user = Users.get_user_by_email(email)

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


@router.post("/wechat/follow-login", response_model=SessionUserResponse)
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
        user_info = await WeChatFollowService.get_wechat_user_info(
            request, form_data.openid
        )

        # 使用openid作为唯一标识
        email = f"{form_data.openid}@wechat.local"

        # 查找或创建用户
        user = Users.get_user_by_email(email)

        if not user:
            # 创建新用户
            user_count = Users.get_num_users()
            role = (
                "admin"
                if user_count == 0
                else request.app.state.config.DEFAULT_USER_ROLE
            )

            # 使用微信昵称作为用户名，如果为空则使用默认名称
            nickname = user_info.get("nickname", "微信用户")
            profile_image_url = user_info.get("headimgurl", "")

            user = Auths.insert_new_auth(
                email=email,
                password=str(uuid.uuid4()),  # 随机密码，微信用户不使用密码登录
                name=nickname,
                role=role,
                profile_image_url=profile_image_url,
            )

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="创建用户失败",
                )

        # 检查是否绑定了手机号
        has_phone = False
        if "@sms.local" in user.email:
            has_phone = True

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

        # 返回结果，包含是否需要绑定手机号的提示
        result = {
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
            "need_bind_phone": not has_phone,  # 是否需要绑定手机号
        }

        return result

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"微信登录失败: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"登录失败: {str(e)}",
        )


@router.post("/wechat/follow-event")
async def wechat_follow_event(request: Request):
    """处理微信公众号关注事件（微信服务器回调）"""
    import xml.etree.ElementTree as ET

    try:
        # 解析微信推送的XML数据
        body = await request.body()
        xml_data = body.decode("utf-8")

        # 解析XML
        root = ET.fromstring(xml_data)

        # 提取关键信息
        msg_type = root.find("MsgType").text if root.find("MsgType") is not None else ""
        event = root.find("Event").text if root.find("Event") is not None else ""
        openid = (
            root.find("FromUserName").text
            if root.find("FromUserName") is not None
            else ""
        )
        scene_str = (
            root.find("EventKey").text if root.find("EventKey") is not None else ""
        )

        # 处理关注事件
        if msg_type == "event" and event == "subscribe":
            # 如果是带参数的关注事件，scene_str格式为qrscene_SCENE_STR
            if scene_str.startswith("qrscene_"):
                scene_id = scene_str[8:]  # 去掉qrscene_前缀
                # 标记用户已关注
                WeChatFollowService.mark_followed(scene_id, openid)
                log.info(f"用户 {openid} 通过场景值 {scene_id} 关注了公众号")
            else:
                log.info(f"用户 {openid} 关注了公众号（无场景值）")

        # 处理扫描事件（已关注用户扫描带参数二维码）
        elif msg_type == "event" and event == "SCAN":
            scene_id = scene_str  # 扫描事件直接返回场景值
            WeChatFollowService.mark_followed(scene_id, openid)
            log.info(f"已关注用户 {openid} 扫描了场景值 {scene_id} 的二维码")

        # 微信要求返回success或空字符串表示成功处理
        return Response(content="success", media_type="text/plain")

    except Exception as e:
        log.error(f"处理微信关注事件失败: {str(e)}")
        # 即使处理失败，也要返回success，避免微信重复推送
        return Response(content="success", media_type="text/plain")


@router.get("/wechat/check/{scene_id}")
async def check_wechat_follow_status(scene_id: str):
    """检查微信关注状态（用于前端轮询）"""
    try:
        status_data = WeChatFollowService.get_follow_status(scene_id)
        return status_data
    except Exception as e:
        log.error(f"检查微信关注状态失败: {str(e)}")
        return {"status": "error", "message": str(e)}


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
    phone_email = f"{phone_number}@sms.local"
    existing_user = Users.get_user_by_email(phone_email)
    if existing_user and existing_user.id != user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="该手机号已被其他用户绑定"
        )

    try:
        # 检查用户当前的登录类型
        current_login_type = getattr(user, "primary_login_type", "email")

        # 如果是微信用户绑定手机号
        if "@wechat.local" in user.email or current_login_type == "wechat":
            # 创建或更新手机号认证记录
            phone_user = Users.get_user_by_email(phone_email)
            if not phone_user:
                # 为微信用户创建手机号登录方式
                phone_user = Auths.insert_new_auth(
                    email=phone_email,
                    password=str(uuid.uuid4()),  # 随机密码，用短信登录
                    name=user.name,
                    role=user.role,
                    profile_image_url=user.profile_image_url,
                    login_type="phone",
                    phone_number=phone_number,
                )

                if not phone_user:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="绑定失败",
                    )

                # 创建绑定关系
                UserBindings.create_binding(
                    primary_user_id=user.id,
                    bound_user_id=phone_user.id,
                    primary_login_type=current_login_type,
                    bound_login_type="phone",
                    binding_data={"phone_number": phone_number},
                )

            # 更新用户信息
            Users.update_user_by_id(
                user.id,
                {
                    "phone_number": phone_number,
                    "available_login_types": f"{getattr(user, 'available_login_types', current_login_type)},phone",
                    "binding_status": {
                        **getattr(user, "binding_status", {}),
                        "phone": "active",
                    },
                },
            )
        else:
            # 邮箱用户直接更新手机号信息
            Users.update_user_by_id(
                user.id,
                {
                    "phone_number": phone_number,
                    "available_login_types": f"{getattr(user, 'available_login_types', 'email')},phone",
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
    request: Request, form_data: BindWeChatForm, user=Depends(get_current_user)
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
    wechat_email = f"{openid}@wechat.local"
    existing_user = Users.get_user_by_email(wechat_email)
    if existing_user and existing_user.id != user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="该微信账号已被其他用户绑定"
        )

    try:
        # 检查用户当前的登录类型
        current_login_type = getattr(user, "primary_login_type", "email")

        # 获取微信用户信息
        user_info = await WeChatFollowService.get_wechat_user_info(request, openid)

        # 如果是手机号或邮箱用户绑定微信
        if "@sms.local" in user.email or current_login_type in ["phone", "email"]:
            # 创建微信认证记录
            wechat_user = Users.get_user_by_email(wechat_email)
            if not wechat_user:
                # 为当前用户创建微信登录方式
                wechat_user = Auths.insert_new_auth(
                    email=wechat_email,
                    password=str(uuid.uuid4()),  # 随机密码，用微信登录
                    name=user.name,
                    role=user.role,
                    profile_image_url=user_info.get(
                        "headimgurl", user.profile_image_url
                    ),
                    login_type="wechat",
                    wechat_openid=openid,
                    wechat_unionid=user_info.get("unionid"),
                    auth_metadata=user_info,
                )

                if not wechat_user:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="绑定失败",
                    )

                # 创建绑定关系
                UserBindings.create_binding(
                    primary_user_id=user.id,
                    bound_user_id=wechat_user.id,
                    primary_login_type=current_login_type,
                    bound_login_type="wechat",
                    binding_data={
                        "openid": openid,
                        "nickname": user_info.get("nickname"),
                    },
                )

            # 更新用户信息
            Users.update_user_by_id(
                user.id,
                {
                    "wechat_openid": openid,
                    "wechat_nickname": user_info.get("nickname"),
                    "available_login_types": f"{getattr(user, 'available_login_types', current_login_type)},wechat",
                    "binding_status": {
                        **getattr(user, "binding_status", {}),
                        "wechat": "active",
                    },
                },
            )
        else:
            # 微信用户直接更新绑定信息
            Users.update_user_by_id(
                user.id,
                {
                    "wechat_nickname": user_info.get("nickname"),
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
