from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from typing import Optional
import random
import time
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
import uuid
import hashlib

app = FastAPI()

# 配置信息 - 替换为你的实际信息
ALIYUN_ACCESS_KEY_ID = "LTAI5tGP9srZhzbdfzCmKpyX"
ALIYUN_ACCESS_KEY_SECRET = "IKqnww2tm63btaCCASo8nutSsKGtVC"
ALIYUN_SIGN_NAME = "为兹科技发展"  # 短信签名
ALIYUN_TEMPLATE_CODE = "SMS_298006018"  # 短信模板CODE
ALIYUN_REGION_ID = ""  # 默认区域

# 模拟数据库存储验证码和用户信息
fake_db = {
    "verification_codes": {},  # 手机号: (验证码, 过期时间)
    "users": {},  # 手机号: 用户信息
}

# 创建阿里云客户端
aliyun_client = AcsClient(
    ALIYUN_ACCESS_KEY_ID, ALIYUN_ACCESS_KEY_SECRET, ALIYUN_REGION_ID
)

# OAuth2 配置
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class PhoneNumberRequest(BaseModel):
    phone_number: str = Field(..., regex=r"^1[3-9]\d{9}$", description="中国大陆手机号")


class VerificationCodeRequest(BaseModel):
    phone_number: str = Field(..., regex=r"^1[3-9]\d{9}$", description="中国大陆手机号")
    verification_code: str = Field(
        ..., min_length=4, max_length=6, description="验证码"
    )


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def generate_verification_code(length=6) -> str:
    """生成指定位数的数字验证码"""
    return "".join([str(random.randint(0, 9)) for _ in range(length)])


def send_sms_via_aliyun(phone_number: str, code: str) -> bool:
    """通过阿里云短信服务发送验证码"""
    request = CommonRequest()
    request.set_accept_format("json")
    request.set_domain("dysmsapi.aliyuncs.com")
    request.set_method("POST")
    request.set_protocol_type("https")
    request.set_version("2017-05-25")
    request.set_action_name("SendSms")

    request.add_query_param("RegionId", ALIYUN_REGION_ID)
    request.add_query_param("PhoneNumbers", phone_number)
    request.add_query_param("SignName", ALIYUN_SIGN_NAME)
    request.add_query_param("TemplateCode", ALIYUN_TEMPLATE_CODE)
    request.add_query_param("TemplateParam", f'{{"code":"{code}"}}')

    try:
        response = aliyun_client.do_action_with_exception(request)
        # 这里可以解析response判断是否发送成功
        # 实际项目中应该处理发送失败的情况
        return True
    except Exception as e:
        print(f"发送短信失败: {e}")
        return False


def generate_token(phone_number: str) -> str:
    """生成简单的token"""
    # 实际项目中应该使用更安全的token生成方式，如JWT
    random_str = str(uuid.uuid4())
    combined = f"{phone_number}:{random_str}"
    return hashlib.sha256(combined.encode()).hexdigest()


@app.post("/request-verification-code")
async def request_verification_code(request: PhoneNumberRequest):
    """请求发送验证码"""
    phone_number = request.phone_number

    # 检查是否频繁请求
    if phone_number in fake_db["verification_codes"]:
        _, expire_time = fake_db["verification_codes"][phone_number]
        if time.time() < expire_time - 240:  # 如果上次发送还在4分钟内
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="请求过于频繁，请稍后再试",
            )

    # 生成验证码
    code = generate_verification_code()
    expire_time = time.time() + 300  # 5分钟后过期

    # 发送短信
    if not send_sms_via_aliyun(phone_number, code):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="短信发送失败"
        )

    # 存储验证码
    fake_db["verification_codes"][phone_number] = (code, expire_time)

    # 开发环境下可以返回验证码方便测试
    return {"message": "验证码已发送", "debug_code": code if app.debug else None}


@app.post("/verify-code-and-login")
async def verify_code_and_login(request: VerificationCodeRequest):
    """验证验证码并登录"""
    phone_number = request.phone_number
    code = request.verification_code

    # 检查验证码是否存在
    if phone_number not in fake_db["verification_codes"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="请先获取验证码"
        )

    stored_code, expire_time = fake_db["verification_codes"][phone_number]

    # 检查验证码是否过期
    if time.time() > expire_time:
        del fake_db["verification_codes"][phone_number]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="验证码已过期，请重新获取"
        )

    # 检查验证码是否正确
    if stored_code != code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="验证码错误"
        )

    # 验证通过，生成token
    token = generate_token(phone_number)

    # 存储用户信息（模拟）
    if phone_number not in fake_db["users"]:
        fake_db["users"][phone_number] = {
            "phone_number": phone_number,
            "token": token,
            "created_at": time.time(),
        }
    else:
        fake_db["users"][phone_number]["token"] = token

    # 删除已使用的验证码
    del fake_db["verification_codes"][phone_number]

    return Token(access_token=token, token_type="bearer")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """获取当前用户"""
    for user in fake_db["users"].values():
        if user["token"] == token:
            return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无效的token",
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.get("/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """获取当前用户信息"""
    return current_user
