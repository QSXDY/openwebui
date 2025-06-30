import time
from typing import Optional

from open_webui.internal.db import Base, JSONField, get_db


from open_webui.models.chats import Chats
from open_webui.models.groups import Groups


from pydantic import BaseModel, ConfigDict
from sqlalchemy import BigInteger, Column, String, Text
from sqlalchemy import or_


####################
# User DB Schema
####################


class User(Base):
    __tablename__ = "user"

    id = Column(String, primary_key=True)
    name = Column(String)
    email = Column(String)
    role = Column(String)
    profile_image_url = Column(Text)

    last_active_at = Column(BigInteger)
    updated_at = Column(BigInteger)
    created_at = Column(BigInteger)

    api_key = Column(String, nullable=True, unique=True)
    settings = Column(JSONField, nullable=True)
    info = Column(JSONField, nullable=True)

    oauth_sub = Column(Text, unique=True)

    # 新增字段支持绑定功能
    primary_login_type = Column(String, default="email")  # 主要登录方式
    available_login_types = Column(String)  # 可用的登录方式，逗号分隔
    phone_number = Column(String)  # 绑定的手机号
    wechat_openid = Column(String)  # 绑定的微信openid
    wechat_nickname = Column(String)  # 微信昵称
    binding_status = Column(JSONField)  # 各种登录方式的绑定状态


class UserSettings(BaseModel):
    ui: Optional[dict] = {}
    model_config = ConfigDict(extra="allow")
    pass


class UserModel(BaseModel):
    id: str
    name: str
    email: str
    role: str = "pending"
    profile_image_url: str

    last_active_at: int  # timestamp in epoch
    updated_at: int  # timestamp in epoch
    created_at: int  # timestamp in epoch

    api_key: Optional[str] = None
    settings: Optional[UserSettings] = None
    info: Optional[dict] = None

    oauth_sub: Optional[str] = None

    # 新增字段
    primary_login_type: Optional[str] = "email"
    available_login_types: Optional[str] = None
    phone_number: Optional[str] = None
    wechat_openid: Optional[str] = None
    wechat_nickname: Optional[str] = None
    binding_status: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True, extra="allow")


####################
# Forms
####################


class UserListResponse(BaseModel):
    users: list[UserModel]
    total: int


class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: str
    profile_image_url: str
    phone_number: Optional[str] = None
    wechat_openid: Optional[str] = None
    wechat_nickname: Optional[str] = None
    primary_login_type: Optional[str] = "email"
    available_login_types: Optional[str] = None
    binding_status: Optional[dict] = None


class UserNameResponse(BaseModel):
    id: str
    name: str
    role: str
    profile_image_url: str


class UserRoleUpdateForm(BaseModel):
    id: str
    role: str


class UserUpdateForm(BaseModel):
    name: str
    email: str
    profile_image_url: str
    password: Optional[str] = None
    credit: Optional[float] = None


class UserCreditUpdateForm(BaseModel):
    amount: Optional[float] = None
    credit: Optional[float] = None


class UserBindingForm(BaseModel):
    """用户绑定表单"""

    login_type: str  # phone, wechat, email
    login_value: str  # 手机号、微信openid或邮箱
    verification_code: Optional[str] = None  # 验证码（如果需要）
    wechat_nickname: Optional[str] = None  # 微信昵称（仅微信绑定时使用）


class UserUnbindingForm(BaseModel):
    """用户解绑表单"""

    login_type: str  # phone, wechat, email
    verification_code: Optional[str] = None  # 验证码（如果需要）


class UserBindingStatusResponse(BaseModel):
    """用户绑定状态响应"""

    user_id: str
    primary_login_type: str
    available_login_types: Optional[str] = None
    binding_status: dict
    internal_binding_status: dict


class UserSwitchPrimaryLoginForm(BaseModel):
    """切换主要登录方式表单"""

    new_primary_login_type: str  # email, phone, wechat


class UsersTable:
    def insert_new_user(
        self,
        id: str,
        name: str,
        email: str,
        profile_image_url: str = "/user.png",
        role: str = "pending",
        oauth_sub: Optional[str] = None,
        primary_login_type: str = "email",
        phone_number: Optional[str] = None,
        wechat_openid: Optional[str] = None,
        wechat_nickname: Optional[str] = None,
    ) -> Optional[UserModel]:
        with get_db() as db:
            user = UserModel(
                **{
                    "id": id,
                    "name": name,
                    "email": email,
                    "role": role,
                    "profile_image_url": profile_image_url,
                    "last_active_at": int(time.time()),
                    "created_at": int(time.time()),
                    "updated_at": int(time.time()),
                    "oauth_sub": oauth_sub,
                    "primary_login_type": primary_login_type,
                    "available_login_types": primary_login_type,
                    "phone_number": phone_number,
                    "wechat_openid": wechat_openid,
                    "wechat_nickname": wechat_nickname,
                    "binding_status": {primary_login_type: "active"},
                }
            )
            result = User(**user.model_dump())
            db.add(result)
            db.commit()
            db.refresh(result)
            if result:
                return user
            else:
                return None

    def get_user_by_id(self, id: str) -> Optional[UserModel]:
        try:
            with get_db() as db:
                user = db.query(User).filter_by(id=id).first()
                return UserModel.model_validate(user)
        except Exception:
            return None

    def get_user_by_api_key(self, api_key: str) -> Optional[UserModel]:
        try:
            with get_db() as db:
                user = db.query(User).filter_by(api_key=api_key).first()
                return UserModel.model_validate(user)
        except Exception:
            return None

    def get_user_by_email(self, email: str) -> Optional[UserModel]:
        try:
            with get_db() as db:
                user = db.query(User).filter_by(email=email).first()
                return UserModel.model_validate(user)
        except Exception:
            return None

    def get_user_by_oauth_sub(self, sub: str) -> Optional[UserModel]:
        try:
            with get_db() as db:
                user = db.query(User).filter_by(oauth_sub=sub).first()
                return UserModel.model_validate(user)
        except Exception:
            return None

    def get_users(
        self,
        filter: Optional[dict] = None,
        skip: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> UserListResponse:
        with get_db() as db:
            query = db.query(User)

            if filter:
                query_key = filter.get("query")
                if query_key:
                    query = query.filter(
                        or_(
                            User.name.ilike(f"%{query_key}%"),
                            User.email.ilike(f"%{query_key}%"),
                        )
                    )

                order_by = filter.get("order_by")
                direction = filter.get("direction")

                if order_by == "name":
                    if direction == "asc":
                        query = query.order_by(User.name.asc())
                    else:
                        query = query.order_by(User.name.desc())
                elif order_by == "email":
                    if direction == "asc":
                        query = query.order_by(User.email.asc())
                    else:
                        query = query.order_by(User.email.desc())

                elif order_by == "created_at":
                    if direction == "asc":
                        query = query.order_by(User.created_at.asc())
                    else:
                        query = query.order_by(User.created_at.desc())

                elif order_by == "last_active_at":
                    if direction == "asc":
                        query = query.order_by(User.last_active_at.asc())
                    else:
                        query = query.order_by(User.last_active_at.desc())

                elif order_by == "updated_at":
                    if direction == "asc":
                        query = query.order_by(User.updated_at.asc())
                    else:
                        query = query.order_by(User.updated_at.desc())
                elif order_by == "role":
                    if direction == "asc":
                        query = query.order_by(User.role.asc())
                    else:
                        query = query.order_by(User.role.desc())

            else:
                query = query.order_by(User.created_at.desc())

            if skip:
                query = query.offset(skip)
            if limit:
                query = query.limit(limit)

            users = query.all()
            return {
                "users": [UserModel.model_validate(user) for user in users],
                "total": db.query(User).count(),
            }

    def get_users_by_user_ids(self, user_ids: list[str]) -> list[UserModel]:
        with get_db() as db:
            users = db.query(User).filter(User.id.in_(user_ids)).all()
            return [UserModel.model_validate(user) for user in users]

    def get_num_users(self) -> Optional[int]:
        with get_db() as db:
            return db.query(User).count()

    def get_first_user(self) -> UserModel:
        try:
            with get_db() as db:
                user = db.query(User).order_by(User.created_at).first()
                return UserModel.model_validate(user)
        except Exception:
            return None

    def get_user_webhook_url_by_id(self, id: str) -> Optional[str]:
        try:
            with get_db() as db:
                user = db.query(User).filter_by(id=id).first()

                if user.settings is None:
                    return None
                else:
                    return (
                        user.settings.get("ui", {})
                        .get("notifications", {})
                        .get("webhook_url", None)
                    )
        except Exception:
            return None

    def update_user_role_by_id(self, id: str, role: str) -> Optional[UserModel]:
        try:
            with get_db() as db:
                db.query(User).filter_by(id=id).update({"role": role})
                db.commit()
                user = db.query(User).filter_by(id=id).first()
                return UserModel.model_validate(user)
        except Exception:
            return None

    def update_user_profile_image_url_by_id(
        self, id: str, profile_image_url: str
    ) -> Optional[UserModel]:
        try:
            with get_db() as db:
                db.query(User).filter_by(id=id).update(
                    {"profile_image_url": profile_image_url}
                )
                db.commit()

                user = db.query(User).filter_by(id=id).first()
                return UserModel.model_validate(user)
        except Exception:
            return None

    def update_user_last_active_by_id(self, id: str) -> Optional[UserModel]:
        try:
            with get_db() as db:
                db.query(User).filter_by(id=id).update(
                    {"last_active_at": int(time.time())}
                )
                db.commit()

                user = db.query(User).filter_by(id=id).first()
                return UserModel.model_validate(user)
        except Exception:
            return None

    def update_user_oauth_sub_by_id(
        self, id: str, oauth_sub: str
    ) -> Optional[UserModel]:
        try:
            with get_db() as db:
                db.query(User).filter_by(id=id).update({"oauth_sub": oauth_sub})
                db.commit()

                user = db.query(User).filter_by(id=id).first()
                return UserModel.model_validate(user)
        except Exception:
            return None

    def update_user_by_id(self, id: str, updated: dict) -> Optional[UserModel]:
        try:
            with get_db() as db:
                db.query(User).filter_by(id=id).update(updated)
                db.commit()

                user = db.query(User).filter_by(id=id).first()
                return UserModel.model_validate(user)
                # return UserModel(**user.dict())
        except Exception:
            return None

    def update_user_settings_by_id(self, id: str, updated: dict) -> Optional[UserModel]:
        try:
            with get_db() as db:
                user_settings = db.query(User).filter_by(id=id).first().settings

                if user_settings is None:
                    user_settings = {}

                user_settings.update(updated)

                db.query(User).filter_by(id=id).update({"settings": user_settings})
                db.commit()

                user = db.query(User).filter_by(id=id).first()
                return UserModel.model_validate(user)
        except Exception:
            return None

    def delete_user_by_id(self, id: str) -> bool:
        try:
            # Remove User from Groups
            Groups.remove_user_from_all_groups(id)

            # Delete User Chats
            result = Chats.delete_chats_by_user_id(id)
            if result:
                with get_db() as db:
                    # Delete User
                    db.query(User).filter_by(id=id).delete()
                    db.commit()

                return True
            else:
                return False
        except Exception:
            return False

    def update_user_api_key_by_id(self, id: str, api_key: str) -> str:
        try:
            with get_db() as db:
                result = db.query(User).filter_by(id=id).update({"api_key": api_key})
                db.commit()
                return True if result == 1 else False
        except Exception:
            return False

    def get_user_api_key_by_id(self, id: str) -> Optional[str]:
        try:
            with get_db() as db:
                user = db.query(User).filter_by(id=id).first()
                return user.api_key
        except Exception:
            return None

    def get_valid_user_ids(self, user_ids: list[str]) -> list[str]:
        with get_db() as db:
            users = db.query(User).filter(User.id.in_(user_ids)).all()
            return [user.id for user in users]

    def get_super_admin_user(self) -> Optional[UserModel]:
        with get_db() as db:
            user = db.query(User).filter_by(role="admin").first()
            if user:
                return UserModel.model_validate(user)
            else:
                return None

    def update_user_binding_info(
        self,
        user_id: str,
        phone_number: Optional[str] = None,
        wechat_openid: Optional[str] = None,
        wechat_nickname: Optional[str] = None,
        login_type: Optional[str] = None,
    ) -> Optional[UserModel]:
        """更新用户绑定信息"""
        try:
            with get_db() as db:
                user = db.query(User).filter_by(id=user_id).first()
                if not user:
                    return None

                update_data = {}

                # 更新手机号绑定
                if phone_number is not None:
                    update_data["phone_number"] = phone_number
                    # 更新可用登录方式
                    available_types = set((user.available_login_types or "").split(","))
                    available_types.discard("")  # 移除空字符串
                    available_types.add("phone")
                    update_data["available_login_types"] = ",".join(available_types)

                    # 更新绑定状态
                    binding_status = user.binding_status or {}
                    binding_status["phone"] = "active"
                    update_data["binding_status"] = binding_status

                # 更新微信绑定
                if wechat_openid is not None:
                    update_data["wechat_openid"] = wechat_openid
                    if wechat_nickname is not None:
                        update_data["wechat_nickname"] = wechat_nickname

                    # 更新可用登录方式
                    available_types = set((user.available_login_types or "").split(","))
                    available_types.discard("")  # 移除空字符串
                    available_types.add("wechat")
                    update_data["available_login_types"] = ",".join(available_types)

                    # 更新绑定状态
                    binding_status = user.binding_status or {}
                    binding_status["wechat"] = "active"
                    update_data["binding_status"] = binding_status

                # 更新主要登录方式
                if login_type is not None:
                    update_data["primary_login_type"] = login_type

                # 更新修改时间
                update_data["updated_at"] = int(time.time())

                # 执行更新
                if update_data:
                    db.query(User).filter_by(id=user_id).update(update_data)
                    db.commit()

                    # 返回更新后的用户信息
                    updated_user = db.query(User).filter_by(id=user_id).first()
                    return UserModel.model_validate(updated_user)

                return UserModel.model_validate(user)
        except Exception as e:
            print(f"更新用户绑定信息失败: {str(e)}")
            return None

    def unbind_user_login_method(
        self, user_id: str, login_type: str
    ) -> Optional[UserModel]:
        """解绑用户登录方式"""
        try:
            with get_db() as db:
                user = db.query(User).filter_by(id=user_id).first()
                if not user:
                    return None

                update_data = {}

                # 解绑手机号
                if login_type == "phone":
                    update_data["phone_number"] = None

                # 解绑微信
                elif login_type == "wechat":
                    update_data["wechat_openid"] = None
                    update_data["wechat_nickname"] = None

                # 更新可用登录方式
                available_types = set((user.available_login_types or "").split(","))
                available_types.discard("")  # 移除空字符串
                available_types.discard(login_type)  # 移除解绑的登录方式
                update_data["available_login_types"] = ",".join(available_types)

                # 更新绑定状态
                binding_status = user.binding_status or {}
                if login_type in binding_status:
                    binding_status[login_type] = "inactive"
                update_data["binding_status"] = binding_status

                # 如果解绑的是主要登录方式，需要切换到其他方式
                if user.primary_login_type == login_type:
                    if "email" in available_types:
                        update_data["primary_login_type"] = "email"
                    elif available_types:
                        update_data["primary_login_type"] = list(available_types)[0]

                # 更新修改时间
                update_data["updated_at"] = int(time.time())

                # 执行更新
                if update_data:
                    db.query(User).filter_by(id=user_id).update(update_data)
                    db.commit()

                    # 返回更新后的用户信息
                    updated_user = db.query(User).filter_by(id=user_id).first()
                    return UserModel.model_validate(updated_user)

                return UserModel.model_validate(user)
        except Exception as e:
            print(f"解绑用户登录方式失败: {str(e)}")
            return None

    def get_user_by_phone_number(self, phone_number: str) -> Optional[UserModel]:
        """根据手机号获取用户信息"""
        try:
            with get_db() as db:
                user = db.query(User).filter_by(phone_number=phone_number).first()
                return UserModel.model_validate(user) if user else None
        except Exception:
            return None

    def get_user_by_wechat_openid(self, wechat_openid: str) -> Optional[UserModel]:
        """根据微信openid获取用户信息"""
        try:
            with get_db() as db:
                user = db.query(User).filter_by(wechat_openid=wechat_openid).first()
                return UserModel.model_validate(user) if user else None
        except Exception:
            return None

    def check_user_binding_status(self, user_id: str) -> dict:
        """检查用户的绑定状态"""
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return {"error": "用户不存在"}

            binding_status = {
                "email": {
                    "bound": bool(user.email),
                    "value": user.email,
                    "is_primary": user.primary_login_type == "email",
                },
                "phone": {
                    "bound": bool(user.phone_number),
                    "value": user.phone_number,
                    "is_primary": user.primary_login_type == "phone",
                },
                "wechat": {
                    "bound": bool(user.wechat_openid),
                    "value": user.wechat_openid,
                    "nickname": user.wechat_nickname,
                    "is_primary": user.primary_login_type == "wechat",
                },
            }

            return {
                "user_id": user_id,
                "primary_login_type": user.primary_login_type,
                "available_login_types": user.available_login_types,
                "binding_status": binding_status,
                "internal_binding_status": user.binding_status or {},
            }
        except Exception as e:
            return {"error": f"检查绑定状态失败: {str(e)}"}

    def check_binding_conflicts(
        self, user_id: str, login_type: str, login_value: str
    ) -> dict:
        """检查绑定是否冲突（是否已被其他用户使用）"""
        try:
            with get_db() as db:
                if login_type == "phone":
                    existing_user = (
                        db.query(User)
                        .filter(User.phone_number == login_value, User.id != user_id)
                        .first()
                    )
                elif login_type == "wechat":
                    existing_user = (
                        db.query(User)
                        .filter(User.wechat_openid == login_value, User.id != user_id)
                        .first()
                    )
                elif login_type == "email":
                    existing_user = (
                        db.query(User)
                        .filter(User.email == login_value, User.id != user_id)
                        .first()
                    )
                else:
                    return {"conflict": False, "message": "不支持的登录类型"}

                if existing_user:
                    return {
                        "conflict": True,
                        "message": f"该{login_type}已被其他用户使用",
                        "existing_user_id": existing_user.id,
                    }
                else:
                    return {"conflict": False, "message": "可以绑定"}
        except Exception as e:
            return {"conflict": True, "message": f"检查冲突时出错: {str(e)}"}

    def get_user_available_login_methods(self, user_id: str) -> list:
        """获取用户可用的登录方式"""
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return []

            methods = []
            if user.email:
                methods.append("email")
            if user.phone_number:
                methods.append("phone")
            if user.wechat_openid:
                methods.append("wechat")

            return methods
        except Exception:
            return []

    def switch_primary_login_type(
        self, user_id: str, new_primary_type: str
    ) -> Optional[UserModel]:
        """切换用户的主要登录方式"""
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return None

            # 检查新的主要登录方式是否已绑定
            if new_primary_type == "email" and not user.email:
                return None
            elif new_primary_type == "phone" and not user.phone_number:
                return None
            elif new_primary_type == "wechat" and not user.wechat_openid:
                return None
            elif new_primary_type not in ["email", "phone", "wechat"]:
                return None

            # 更新主要登录方式
            return self.update_user_by_id(
                user_id,
                {
                    "primary_login_type": new_primary_type,
                    "updated_at": int(time.time()),
                },
            )
        except Exception as e:
            print(f"切换主要登录方式失败: {str(e)}")
            return None


Users = UsersTable()
