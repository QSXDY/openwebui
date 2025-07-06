import logging
import uuid
from typing import Optional

from open_webui.internal.db import Base, JSONField, get_db
from open_webui.models.users import UserModel, Users
from open_webui.env import SRC_LOG_LEVELS
from pydantic import BaseModel
from sqlalchemy import (
    Boolean,
    Column,
    String,
    Text,
    BigInteger,
    ForeignKey,
    UniqueConstraint,
)

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MODELS"])

####################
# DB MODEL
####################


class Auth(Base):
    __tablename__ = "auth"

    id = Column(String, primary_key=True)
    email = Column(String)
    password = Column(Text)
    active = Column(Boolean)

    # 新增字段支持多种登录方式
    login_type = Column(String(20), default="email")  # email, phone, wechat
    external_id = Column(String)  # 外部系统ID（如微信openid）
    phone_number = Column(String(20))  # 手机号
    wechat_openid = Column(String)  # 微信openid
    wechat_unionid = Column(String)  # 微信unionid
    auth_metadata = Column(JSONField)  # 认证相关的元数据


class UserBinding(Base):
    __tablename__ = "user_bindings"

    id = Column(String, primary_key=True)
    primary_user_id = Column(String, ForeignKey("user.id"), nullable=False)
    bound_user_id = Column(String, ForeignKey("user.id"), nullable=False)
    primary_login_type = Column(String(20), nullable=False)  # email, phone, wechat
    bound_login_type = Column(String(20), nullable=False)  # email, phone, wechat
    binding_status = Column(String(20), nullable=False, default="active")
    binding_data = Column(JSONField)
    created_at = Column(BigInteger)
    updated_at = Column(BigInteger)

    __table_args__ = (
        UniqueConstraint(
            "primary_user_id", "bound_user_id", name="uq_user_binding_pair"
        ),
    )


class AuthModel(BaseModel):
    id: str
    email: str
    password: str
    active: bool = True

    # 新增字段
    login_type: str = "email"
    external_id: Optional[str] = None
    phone_number: Optional[str] = None
    wechat_openid: Optional[str] = None
    wechat_unionid: Optional[str] = None
    auth_metadata: Optional[dict] = None


class UserBindingModel(BaseModel):
    id: str
    primary_user_id: str
    bound_user_id: str
    primary_login_type: str
    bound_login_type: str
    binding_status: str = "active"
    binding_data: Optional[dict] = None
    created_at: Optional[int] = None
    updated_at: Optional[int] = None


####################
# Forms
####################


class Token(BaseModel):
    token: str
    token_type: str


class ApiKey(BaseModel):
    api_key: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    profile_image_url: str
    phone_number: Optional[str] = None
    wechat_openid: Optional[str] = None
    wechat_nickname: Optional[str] = None
    primary_login_type: Optional[str] = "email"
    available_login_types: Optional[str] = None
    binding_status: Optional[dict] = None


class SigninResponse(Token, UserResponse):
    pass


class SigninForm(BaseModel):
    email: str
    password: str


class LdapForm(BaseModel):
    user: str
    password: str


class ProfileImageUrlForm(BaseModel):
    profile_image_url: str


class UpdateProfileForm(BaseModel):
    profile_image_url: str
    name: str


class UpdatePasswordForm(BaseModel):
    password: str
    new_password: str


class SignupForm(BaseModel):
    name: str
    email: str
    password: str
    profile_image_url: Optional[str] = "/user.png"


class AddUserForm(SignupForm):
    role: Optional[str] = "pending"


class AuthsTable:
    def insert_new_auth(
        self,
        email: Optional[str] = None,
        password: str = "",
        name: str = "",
        profile_image_url: str = "/user.png",
        role: str = "pending",
        oauth_sub: Optional[str] = None,
        login_type: str = "email",
        external_id: Optional[str] = None,
        phone_number: Optional[str] = None,
        wechat_openid: Optional[str] = None,
        wechat_unionid: Optional[str] = None,
        auth_metadata: Optional[dict] = None,
    ) -> Optional[UserModel]:
        with get_db() as db:
            log.info(f"insert_new_auth: login_type={login_type}")

            id = str(uuid.uuid4())

            # 根据登录类型设置email字段
            if login_type == "phone" and phone_number:
                # 手机号登录，email可以为空或设置为None
                final_email = email if email else None
            elif login_type == "wechat" and wechat_openid:
                # 微信登录，email可以为空或设置为None
                final_email = email if email else None
            else:
                # 邮箱登录，必须有email
                if not email:
                    log.error(f"Email required for login_type: {login_type}")
                    return None
                final_email = email

            auth = AuthModel(
                **{
                    "id": id,
                    "email": final_email or "",  # 如果为None则设置为空字符串
                    "password": password,
                    "active": True,
                    "login_type": login_type,
                    "external_id": external_id,
                    "phone_number": phone_number,
                    "wechat_openid": wechat_openid,
                    "wechat_unionid": wechat_unionid,
                    "auth_metadata": auth_metadata,
                }
            )
            result = Auth(**auth.model_dump())
            db.add(result)

            # 设置用户的绑定信息
            user_phone_number = phone_number if login_type == "phone" else None
            user_wechat_openid = wechat_openid if login_type == "wechat" else None
            user_wechat_nickname = (
                auth_metadata.get("nickname")
                if auth_metadata and login_type == "wechat"
                else None
            )

            user = Users.insert_new_user(
                id,
                name,
                final_email or "",  # 用户表也使用相同的email处理逻辑
                profile_image_url,
                role,
                oauth_sub,
                primary_login_type=login_type,
                phone_number=user_phone_number,
                wechat_openid=user_wechat_openid,
                wechat_nickname=user_wechat_nickname,
            )

            # 确保用户的绑定信息被正确设置
            if user and (user_phone_number or user_wechat_openid):
                Users.update_user_binding_info(
                    user_id=id,
                    phone_number=user_phone_number,
                    wechat_openid=user_wechat_openid,
                    wechat_nickname=user_wechat_nickname,
                    login_type=login_type,
                )

            db.commit()
            db.refresh(result)

            if result and user:
                return user
            else:
                return None

    def authenticate_user(self, email: str, password: str) -> Optional[UserModel]:
        # to avoid cycle-import error
        from open_webui.utils.auth import verify_password

        log.info(f"authenticate_user: {email}")
        try:
            with get_db() as db:
                auth = db.query(Auth).filter_by(email=email, active=True).first()
                if auth:
                    if verify_password(password, auth.password):
                        user = Users.get_user_by_id(auth.id)
                        return user
                    else:
                        return None
                else:
                    return None
        except Exception:
            return None

    def authenticate_user_by_api_key(self, api_key: str) -> Optional[UserModel]:
        log.info(f"authenticate_user_by_api_key: {api_key}")
        # if no api_key, return None
        if not api_key:
            return None

        try:
            user = Users.get_user_by_api_key(api_key)
            return user if user else None
        except Exception:
            return False

    def authenticate_user_by_trusted_header(self, email: str) -> Optional[UserModel]:
        log.info(f"authenticate_user_by_trusted_header: {email}")
        try:
            with get_db() as db:
                auth = db.query(Auth).filter_by(email=email, active=True).first()
                if auth:
                    user = Users.get_user_by_id(auth.id)
                    return user
        except Exception:
            return None

    def authenticate_user_by_phone(self, phone_number: str) -> Optional[UserModel]:
        """通过手机号进行用户认证（用于短信验证码登录）"""
        log.info(f"authenticate_user_by_phone: {phone_number}")
        try:
            with get_db() as db:
                auth = (
                    db.query(Auth)
                    .filter_by(phone_number=phone_number, active=True)
                    .first()
                )
                if auth:
                    user = Users.get_user_by_id(auth.id)
                    return user
                else:
                    return None
        except Exception:
            return None

    def authenticate_user_by_wechat_openid(
        self, wechat_openid: str
    ) -> Optional[UserModel]:
        """通过微信openid进行用户认证"""
        log.info(f"authenticate_user_by_wechat_openid: {wechat_openid}")
        try:
            with get_db() as db:
                auth = (
                    db.query(Auth)
                    .filter_by(wechat_openid=wechat_openid, active=True)
                    .first()
                )
                if auth:
                    user = Users.get_user_by_id(auth.id)
                    return user
                else:
                    return None
        except Exception:
            return None

    def update_user_password_by_id(self, id: str, new_password: str) -> bool:
        try:
            with get_db() as db:
                result = (
                    db.query(Auth).filter_by(id=id).update({"password": new_password})
                )
                db.commit()
                return True if result == 1 else False
        except Exception:
            return False

    def update_email_by_id(self, id: str, email: str) -> bool:
        try:
            with get_db() as db:
                result = db.query(Auth).filter_by(id=id).update({"email": email})
                db.commit()
                return True if result == 1 else False
        except Exception:
            return False

    def delete_auth_by_id(self, id: str) -> bool:
        try:
            with get_db() as db:
                # Delete User
                result = Users.delete_user_by_id(id)

                if result:
                    db.query(Auth).filter_by(id=id).delete()
                    db.commit()

                    return True
                else:
                    return False
        except Exception:
            return False

    def get_auth_by_login_info(
        self, login_type: str, login_value: str
    ) -> Optional[AuthModel]:
        """根据登录类型和值获取认证信息"""
        try:
            with get_db() as db:
                if login_type == "email":
                    auth = (
                        db.query(Auth).filter_by(email=login_value, active=True).first()
                    )
                elif login_type == "phone":
                    auth = (
                        db.query(Auth)
                        .filter_by(phone_number=login_value, active=True)
                        .first()
                    )
                elif login_type == "wechat":
                    auth = (
                        db.query(Auth)
                        .filter_by(wechat_openid=login_value, active=True)
                        .first()
                    )
                else:
                    return None

                if auth:
                    return AuthModel.model_validate(auth)
                return None
        except Exception:
            return None

    def get_auth_by_id(self, user_id: str) -> Optional[AuthModel]:
        """根据用户ID获取认证信息"""
        try:
            with get_db() as db:
                auth = db.query(Auth).filter_by(id=user_id, active=True).first()
                if auth:
                    return AuthModel.model_validate(auth)
                return None
        except Exception:
            return None

    def get_auth_by_phone_number(self, phone_number: str) -> Optional[AuthModel]:
        """根据手机号获取认证信息"""
        try:
            with get_db() as db:
                auth = (
                    db.query(Auth)
                    .filter_by(phone_number=phone_number, active=True)
                    .first()
                )
                if auth:
                    return AuthModel.model_validate(auth)
                return None
        except Exception:
            return None

    def get_auth_by_wechat_openid(self, wechat_openid: str) -> Optional[AuthModel]:
        """根据微信openid获取认证信息"""
        try:
            with get_db() as db:
                auth = (
                    db.query(Auth)
                    .filter_by(wechat_openid=wechat_openid, active=True)
                    .first()
                )
                if auth:
                    return AuthModel.model_validate(auth)
                return None
        except Exception:
            return None

    # ==== 重构后的核心绑定逻辑 ====

    def find_existing_user(
        self, phone_number: Optional[str] = None, wechat_openid: Optional[str] = None
    ) -> Optional[UserModel]:
        """
        查找现有用户 - 统一的账号查找逻辑
        优先级：手机号 > 微信号
        返回第一个找到的用户，确保不会有重复用户
        """
        try:
            # 先通过手机号查找
            if phone_number:
                # 从Auth表查找
                phone_auth = self.get_auth_by_phone_number(phone_number)
                if phone_auth:
                    user = Users.get_user_by_id(phone_auth.id)
                    if user:
                        return user

                # 从User表查找（兜底）
                user = Users.get_user_by_phone_number(phone_number)
                if user:
                    return user

            # 再通过微信号查找
            if wechat_openid:
                # 从Auth表查找
                wechat_auth = self.get_auth_by_wechat_openid(wechat_openid)
                if wechat_auth:
                    user = Users.get_user_by_id(wechat_auth.id)
                    if user:
                        return user

                # 从User表查找（兜底）
                user = Users.get_user_by_wechat_openid(wechat_openid)
                if user:
                    return user

            return None
        except Exception as e:
            log.error(f"查找现有用户失败: {str(e)}")
            return None

    def bind_login_methods_to_user(
        self,
        user_id: str,
        phone_number: Optional[str] = None,
        wechat_openid: Optional[str] = None,
        wechat_unionid: Optional[str] = None,
        wechat_nickname: Optional[str] = None,
        auth_metadata: Optional[dict] = None,
    ) -> bool:
        """
        将登录方式绑定到现有用户
        确保Auth表和User表数据同步
        """
        try:
            with get_db() as db:
                # 更新Auth表
                update_data = {}
                if phone_number:
                    update_data["phone_number"] = phone_number
                if wechat_openid:
                    update_data["wechat_openid"] = wechat_openid
                if wechat_unionid:
                    update_data["wechat_unionid"] = wechat_unionid
                if auth_metadata:
                    update_data["auth_metadata"] = auth_metadata

                if update_data:
                    result = db.query(Auth).filter_by(id=user_id).update(update_data)
                    db.commit()

                    if result != 1:
                        log.error(f"更新Auth表失败: user_id={user_id}")
                        return False

                # 更新User表
                user_update_data = {}
                if phone_number:
                    user_update_data["phone_number"] = phone_number
                if wechat_openid:
                    user_update_data["wechat_openid"] = wechat_openid
                if wechat_nickname:
                    user_update_data["wechat_nickname"] = wechat_nickname

                # 更新可用登录方式
                user = Users.get_user_by_id(user_id)
                if user:
                    current_types = set(
                        (
                            user.available_login_types or user.primary_login_type or ""
                        ).split(",")
                    )
                    current_types.discard("")  # 移除空字符串

                    if phone_number:
                        current_types.add("phone")
                    if wechat_openid:
                        current_types.add("wechat")
                    if user.email and not user.email.endswith(
                        ("@sms.local", "@wechat.local")
                    ):
                        current_types.add("email")

                    user_update_data["available_login_types"] = ",".join(
                        sorted(current_types)
                    )

                    # 更新绑定状态
                    binding_status = user.binding_status or {}
                    if phone_number:
                        binding_status["phone"] = "active"
                    if wechat_openid:
                        binding_status["wechat"] = "active"
                    user_update_data["binding_status"] = binding_status

                if user_update_data:
                    success = Users.update_user_by_id(user_id, user_update_data)
                    if not success:
                        log.error(f"更新User表失败: user_id={user_id}")
                        return False

                log.info(
                    f"成功绑定登录方式到用户: user_id={user_id}, phone={bool(phone_number)}, wechat={bool(wechat_openid)}"
                )
                return True

        except Exception as e:
            log.error(f"绑定登录方式失败: {str(e)}")
            return False

    def validate_binding_constraints(
        self,
        phone_number: Optional[str] = None,
        wechat_openid: Optional[str] = None,
        exclude_user_id: Optional[str] = None,
    ) -> dict:
        """
        验证绑定约束条件
        确保手机号和微信号的唯一性
        """
        errors = []
        conflicts = {}

        try:
            # 检查手机号冲突
            if phone_number:
                phone_auth = self.get_auth_by_phone_number(phone_number)
                if phone_auth and phone_auth.id != exclude_user_id:
                    errors.append(f"手机号 {phone_number} 已被其他用户使用")
                    conflicts["phone"] = phone_auth.id

                # 同时检查User表
                phone_user = Users.get_user_by_phone_number(phone_number)
                if phone_user and phone_user.id != exclude_user_id:
                    if "phone" not in conflicts:
                        errors.append(f"手机号 {phone_number} 已被其他用户使用")
                        conflicts["phone"] = phone_user.id

            # 检查微信号冲突
            if wechat_openid:
                wechat_auth = self.get_auth_by_wechat_openid(wechat_openid)
                if wechat_auth and wechat_auth.id != exclude_user_id:
                    errors.append(f"微信账号已被其他用户使用")
                    conflicts["wechat"] = wechat_auth.id

                # 同时检查User表
                wechat_user = Users.get_user_by_wechat_openid(wechat_openid)
                if wechat_user and wechat_user.id != exclude_user_id:
                    if "wechat" not in conflicts:
                        errors.append(f"微信账号已被其他用户使用")
                        conflicts["wechat"] = wechat_user.id

            return {"valid": len(errors) == 0, "errors": errors, "conflicts": conflicts}

        except Exception as e:
            return {
                "valid": False,
                "errors": [f"验证过程出错: {str(e)}"],
                "conflicts": {},
            }

    def create_or_merge_user_account(
        self,
        phone_number: Optional[str] = None,
        wechat_openid: Optional[str] = None,
        wechat_unionid: Optional[str] = None,
        wechat_nickname: Optional[str] = None,
        auth_metadata: Optional[dict] = None,
        user_name: Optional[str] = None,
        password: Optional[str] = None,
        role: str = "user",
    ) -> dict:
        """
        统一的用户账号创建或合并逻辑
        """
        try:
            # 1. 验证绑定约束
            validation = self.validate_binding_constraints(
                phone_number=phone_number, wechat_openid=wechat_openid
            )

            if not validation["valid"]:
                return {
                    "success": False,
                    "action": "validation_failed",
                    "user": None,
                    "message": "; ".join(validation["errors"]),
                    "conflicts": validation["conflicts"],
                }

            # 2. 查找现有用户
            existing_user = self.find_existing_user(
                phone_number=phone_number, wechat_openid=wechat_openid
            )

            if existing_user:
                # 3. 合并到现有用户
                success = self.bind_login_methods_to_user(
                    user_id=existing_user.id,
                    phone_number=phone_number,
                    wechat_openid=wechat_openid,
                    wechat_unionid=wechat_unionid,
                    wechat_nickname=wechat_nickname,
                    auth_metadata=auth_metadata,
                )

                if success:
                    # 如果提供了密码，更新密码
                    if password:
                        self.update_user_password_by_id(existing_user.id, password)

                    # 如果提供了用户名，更新用户名
                    if user_name:
                        Users.update_user_by_id(existing_user.id, {"name": user_name})

                    # 重新获取更新后的用户信息
                    updated_user = Users.get_user_by_id(existing_user.id)
                    return {
                        "success": True,
                        "action": "merged_to_existing",
                        "user": updated_user,
                        "message": "已绑定到现有账号",
                    }
                else:
                    return {
                        "success": False,
                        "action": "merge_failed",
                        "user": None,
                        "message": "绑定到现有账号失败",
                    }
            else:
                # 4. 创建新用户

                # 确定主要登录方式
                primary_login_type = "phone" if phone_number else "wechat"

                # 准备用户信息
                final_name = (
                    user_name
                    or wechat_nickname
                    or f"用户_{phone_number[-4:] if phone_number else wechat_openid[-8:]}"
                )
                final_password = password or str(
                    uuid.uuid4()
                )  # 如果没有密码则生成随机密码

                # 设置头像
                profile_image_url = "/user.png"
                if auth_metadata and auth_metadata.get("headimgurl"):
                    profile_image_url = auth_metadata["headimgurl"]
                elif wechat_openid:
                    import hashlib

                    avatar_hash = hashlib.md5(wechat_openid.encode()).hexdigest()
                    profile_image_url = f"https://www.gravatar.com/avatar/{avatar_hash}?d=identicon&s=200"

                new_user = self.insert_new_auth(
                    email=None,
                    password=final_password,
                    name=final_name,
                    profile_image_url=profile_image_url,
                    role=role,
                    login_type=primary_login_type,
                    phone_number=phone_number,
                    wechat_openid=wechat_openid,
                    wechat_unionid=wechat_unionid,
                    auth_metadata=auth_metadata,
                )

                if new_user:
                    # 确保绑定信息正确
                    self.bind_login_methods_to_user(
                        user_id=new_user.id,
                        phone_number=phone_number,
                        wechat_openid=wechat_openid,
                        wechat_unionid=wechat_unionid,
                        wechat_nickname=wechat_nickname,
                        auth_metadata=auth_metadata,
                    )

                    # 重新获取用户信息确保数据一致
                    final_user = Users.get_user_by_id(new_user.id)
                    return {
                        "success": True,
                        "action": "created_new",
                        "user": final_user,
                        "message": "新账号创建成功",
                    }
                else:
                    return {
                        "success": False,
                        "action": "create_failed",
                        "user": None,
                        "message": "创建新账号失败",
                    }

        except Exception as e:
            log.error(f"创建或合并用户账号失败: {str(e)}")
            return {
                "success": False,
                "action": "error",
                "user": None,
                "message": f"处理失败: {str(e)}",
            }

    # ==== 保持兼容性的旧方法（标记为废弃） ====

    def update_auth_binding_info(self, user_id: str, login_type: str, **kwargs) -> bool:
        """更新认证绑定信息（兼容性方法，建议使用 bind_login_methods_to_user）"""
        try:
            return self.bind_login_methods_to_user(
                user_id=user_id,
                phone_number=kwargs.get("phone_number"),
                wechat_openid=kwargs.get("wechat_openid"),
                wechat_unionid=kwargs.get("wechat_unionid"),
                wechat_nickname=kwargs.get("wechat_nickname")
                or (
                    kwargs.get("auth_metadata", {}).get("nickname")
                    if kwargs.get("auth_metadata")
                    else None
                ),
                auth_metadata=kwargs.get("auth_metadata"),
            )
        except Exception as e:
            log.error(f"更新认证绑定信息失败: {str(e)}")
            return False

    def check_and_merge_wechat_phone_binding(
        self,
        phone_number: str,
        wechat_openid: str,
        wechat_nickname: Optional[str] = None,
        auth_metadata: Optional[dict] = None,
    ) -> dict:
        """
        检查并处理微信和手机号的绑定关系（兼容性方法）
        建议使用 create_or_merge_user_account
        """
        try:
            result = self.create_or_merge_user_account(
                phone_number=phone_number,
                wechat_openid=wechat_openid,
                wechat_nickname=wechat_nickname,
                auth_metadata=auth_metadata,
            )

            # 转换为旧格式的返回值
            if result["success"]:
                if result["action"] == "created_new":
                    return {
                        "action": "create_new",
                        "can_proceed": True,
                        "merged": False,
                        "user": result["user"],
                        "message": result["message"],
                    }
                elif result["action"] == "merged_to_existing":
                    return {
                        "action": "merge_to_existing",
                        "can_proceed": True,
                        "merged": True,
                        "user": result["user"],
                        "message": result["message"],
                    }
            else:
                return {
                    "action": "conflict",
                    "can_proceed": False,
                    "merged": False,
                    "user": None,
                    "message": result["message"],
                }

        except Exception as e:
            return {
                "action": "error",
                "can_proceed": False,
                "merged": False,
                "user": None,
                "message": f"检查绑定关系时出错: {str(e)}",
            }

    def check_binding_availability(self, login_type: str, login_value: str) -> bool:
        """检查绑定信息是否可用（未被其他用户使用）"""
        validation = self.validate_binding_constraints(
            phone_number=login_value if login_type == "phone" else None,
            wechat_openid=login_value if login_type == "wechat" else None,
        )
        return validation["valid"]

    def try_merge_accounts(
        self,
        phone_number: str,
        wechat_openid: str,
        wechat_nickname: Optional[str] = None,
        auth_metadata: Optional[dict] = None,
    ) -> dict:
        """尝试合并账号（兼容性方法）"""
        return self.check_and_merge_wechat_phone_binding(
            phone_number=phone_number,
            wechat_openid=wechat_openid,
            wechat_nickname=wechat_nickname,
            auth_metadata=auth_metadata,
        )


class UserBindingsTable:
    def create_binding(
        self,
        primary_user_id: str,
        bound_user_id: str,
        primary_login_type: str,
        bound_login_type: str,
        binding_data: Optional[dict] = None,
    ) -> bool:
        """创建用户绑定关系"""
        try:
            with get_db() as db:
                import time

                binding = UserBindingModel(
                    id=str(uuid.uuid4()),
                    primary_user_id=primary_user_id,
                    bound_user_id=bound_user_id,
                    primary_login_type=primary_login_type,
                    bound_login_type=bound_login_type,
                    binding_status="active",
                    binding_data=binding_data,
                    created_at=int(time.time()),
                    updated_at=int(time.time()),
                )

                result = UserBinding(**binding.model_dump())
                db.add(result)
                db.commit()
                return True
        except Exception as e:
            log.error(f"创建绑定关系失败: {str(e)}")
            return False

    def get_bindings_by_user_id(self, user_id: str) -> list[UserBindingModel]:
        """获取用户的所有绑定关系"""
        try:
            with get_db() as db:
                bindings = (
                    db.query(UserBinding)
                    .filter(
                        (UserBinding.primary_user_id == user_id)
                        | (UserBinding.bound_user_id == user_id)
                    )
                    .filter_by(binding_status="active")
                    .all()
                )

                return [
                    UserBindingModel.model_validate(binding) for binding in bindings
                ]
        except Exception:
            return []

    def remove_binding(self, primary_user_id: str, bound_user_id: str) -> bool:
        """删除绑定关系"""
        try:
            with get_db() as db:
                result = (
                    db.query(UserBinding)
                    .filter_by(
                        primary_user_id=primary_user_id, bound_user_id=bound_user_id
                    )
                    .update({"binding_status": "inactive"})
                )
                db.commit()
                return result > 0
        except Exception:
            return False


Auths = AuthsTable()
UserBindings = UserBindingsTable()

"""
使用账号合并功能的示例：

# 在微信+手机号注册/绑定流程中
def handle_wechat_phone_binding(phone_number: str, wechat_openid: str, wechat_nickname: str):
    # 检查并处理绑定关系
    result = Auths.check_and_merge_wechat_phone_binding(
        phone_number=phone_number,
        wechat_openid=wechat_openid,
        wechat_nickname=wechat_nickname,
        auth_metadata={"nickname": wechat_nickname}
    )
    
    if result["action"] == "create_new":
        # 创建新账号
        user = Auths.insert_new_auth(
            email=f"{phone_number}@sms.local",  # 使用虚拟邮箱
            password="",  # 第三方登录可以无密码
            name=wechat_nickname,
            login_type="phone",
            phone_number=phone_number,
            wechat_openid=wechat_openid,
            auth_metadata={"nickname": wechat_nickname}
        )
        return {"success": True, "user": user, "message": "新账号创建成功"}
        
    elif result["action"] in ["merge_to_wechat", "merge_to_phone", "same_account"]:
        # 账号合并成功或已是同一账号
        return {
            "success": True, 
            "user": result["user"], 
            "message": result["message"]
        }
        
    else:
        # 冲突或错误
        return {
            "success": False, 
            "message": result["message"]
        }

# 单独的账号合并检查
def try_merge_accounts_example(phone_number: str, wechat_openid: str):
    merge_result = Auths.try_merge_accounts(
        phone_number=phone_number,
        wechat_openid=wechat_openid,
        wechat_nickname="用户昵称"
    )
    
    if merge_result["can_merge"] and merge_result.get("merged"):
        return merge_result["user"]
    else:
        print(f"无法合并账号: {merge_result.get('reason')}")
        return None
"""
