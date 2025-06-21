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
        email: str,
        password: str,
        name: str,
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
            log.info("insert_new_auth")

            id = str(uuid.uuid4())

            auth = AuthModel(
                **{
                    "id": id,
                    "email": email,
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
                email,
                profile_image_url,
                role,
                oauth_sub,
                primary_login_type=login_type,
                phone_number=user_phone_number,
                wechat_openid=user_wechat_openid,
                wechat_nickname=user_wechat_nickname,
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

    def update_auth_binding_info(self, user_id: str, login_type: str, **kwargs) -> bool:
        """更新认证绑定信息"""
        try:
            with get_db() as db:
                update_data = {}
                if login_type == "phone" and "phone_number" in kwargs:
                    update_data["phone_number"] = kwargs["phone_number"]
                elif login_type == "wechat":
                    if "wechat_openid" in kwargs:
                        update_data["wechat_openid"] = kwargs["wechat_openid"]
                    if "wechat_unionid" in kwargs:
                        update_data["wechat_unionid"] = kwargs["wechat_unionid"]
                    if "auth_metadata" in kwargs:
                        update_data["auth_metadata"] = kwargs["auth_metadata"]

                if update_data:
                    result = db.query(Auth).filter_by(id=user_id).update(update_data)
                    db.commit()
                    return result == 1
                return False
        except Exception:
            return False


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
