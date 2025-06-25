import json
import logging
import time
from typing import Optional
import uuid

from open_webui.internal.db import Base, get_db
from open_webui.env import SRC_LOG_LEVELS

from open_webui.models.files import FileMetadataResponse


from pydantic import BaseModel, ConfigDict
from sqlalchemy import (
    BigInteger,
    Column,
    String,
    Text,
    JSON,
    func,
    Boolean,
    ForeignKey,
    and_,
)


log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MODELS"])

####################
# UserGroup DB Schema
####################


class Group(Base):
    __tablename__ = "group"

    id = Column(Text, unique=True, primary_key=True)
    user_id = Column(Text)

    name = Column(Text)
    description = Column(Text)

    data = Column(JSON, nullable=True)
    meta = Column(JSON, nullable=True)

    permissions = Column(JSON, nullable=True)
    user_ids = Column(JSON, nullable=True)
    admin_id = Column(Text, nullable=True)  # spj新增管理员ID字段

    created_at = Column(BigInteger)
    updated_at = Column(BigInteger)


class UserGroupMembership(Base):
    __tablename__ = "user_group_membership"

    id = Column(Text, primary_key=True)
    user_id = Column(Text, nullable=False, index=True)
    group_id = Column(
        Text, ForeignKey("group.id", ondelete="CASCADE"), nullable=False, index=True
    )
    joined_at = Column(BigInteger, nullable=False)  # 加入时间
    is_active = Column(Boolean, nullable=False, default=True)  # 是否活跃
    created_at = Column(BigInteger, nullable=False)
    updated_at = Column(BigInteger, nullable=False)


class GroupModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    user_id: str

    name: str
    description: str

    data: Optional[dict] = None
    meta: Optional[dict] = None

    permissions: Optional[dict] = None
    user_ids: list[str] = []
    admin_id: Optional[str] = None  # 新增管理员ID字段

    created_at: int  # timestamp in epoch
    updated_at: int  # timestamp in epoch


class UserGroupMembershipModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    user_id: str
    group_id: str
    joined_at: int
    is_active: bool = True
    created_at: int
    updated_at: int


####################
# Forms
####################


class GroupResponse(BaseModel):
    id: str
    user_id: str
    name: str
    description: str
    permissions: Optional[dict] = None
    data: Optional[dict] = None
    meta: Optional[dict] = None
    user_ids: list[str] = []
    admin_id: Optional[str] = None  # 新增管理员ID字段
    created_at: int  # timestamp in epoch
    updated_at: int  # timestamp in epoch


class GroupForm(BaseModel):
    name: str
    description: str
    permissions: Optional[dict] = None


class GroupUpdateForm(GroupForm):
    user_ids: Optional[list[str]] = None
    admin_id: Optional[str] = None  # 新增管理员ID字段


class GroupAdminForm(BaseModel):
    admin_id: str  # 设置管理员的表单


class GroupTable:
    def insert_new_group(
        self, user_id: str, form_data: GroupForm
    ) -> Optional[GroupModel]:
        with get_db() as db:
            group = GroupModel(
                **{
                    **form_data.model_dump(exclude_none=True),
                    "id": str(uuid.uuid4()),
                    "user_id": user_id,
                    "created_at": int(time.time()),
                    "updated_at": int(time.time()),
                }
            )

            try:
                result = Group(**group.model_dump())
                db.add(result)
                db.commit()
                db.refresh(result)
                if result:
                    return GroupModel.model_validate(result)
                else:
                    return None

            except Exception:
                return None

    def get_groups(self) -> list[GroupModel]:
        with get_db() as db:
            return [
                GroupModel.model_validate(group)
                for group in db.query(Group).order_by(Group.updated_at.desc()).all()
            ]

    def get_groups_by_member_id(self, user_id: str) -> list[GroupModel]:
        with get_db() as db:
            return [
                GroupModel.model_validate(group)
                for group in db.query(Group)
                .filter(
                    func.json_array_length(Group.user_ids) > 0
                )  # Ensure array exists
                .filter(
                    Group.user_ids.cast(String).like(f'%"{user_id}"%')
                )  # String-based check
                .order_by(Group.updated_at.desc())
                .all()
            ]

    def get_group_by_id(self, id: str) -> Optional[GroupModel]:
        try:
            with get_db() as db:
                group = db.query(Group).filter_by(id=id).first()
                return GroupModel.model_validate(group) if group else None
        except Exception:
            return None

    def get_group_user_ids_by_id(self, id: str) -> Optional[str]:
        group = self.get_group_by_id(id)
        if group:
            return group.user_ids
        else:
            return None

    def update_group_by_id(
        self, id: str, form_data: GroupUpdateForm, overwrite: bool = False
    ) -> Optional[GroupModel]:
        try:
            with get_db() as db:
                db.query(Group).filter_by(id=id).update(
                    {
                        **form_data.model_dump(exclude_none=True),
                        "updated_at": int(time.time()),
                    }
                )
                db.commit()
                return self.get_group_by_id(id=id)
        except Exception as e:
            log.exception(e)
            return None

    def delete_group_by_id(self, id: str) -> bool:
        try:
            with get_db() as db:
                db.query(Group).filter_by(id=id).delete()
                db.commit()
                return True
        except Exception:
            return False

    def delete_all_groups(self) -> bool:
        with get_db() as db:
            try:
                db.query(Group).delete()
                db.commit()

                return True
            except Exception:
                return False

    def remove_user_from_all_groups(self, user_id: str) -> bool:
        with get_db() as db:
            try:
                groups = self.get_groups_by_member_id(user_id)

                for group in groups:
                    group.user_ids.remove(user_id)
                    db.query(Group).filter_by(id=group.id).update(
                        {
                            "user_ids": group.user_ids,
                            "updated_at": int(time.time()),
                        }
                    )
                    db.commit()

                return True
            except Exception:
                return False

    def set_group_admin_by_id(self, id: str, admin_id: str) -> Optional[GroupModel]:
        """设置权限组管理员"""
        try:
            with get_db() as db:
                # 确保管理员是组内成员
                group = self.get_group_by_id(id)
                if not group:
                    return None

                # 如果管理员不在组内，先添加到组内
                if admin_id not in group.user_ids:
                    group.user_ids.append(admin_id)

                db.query(Group).filter_by(id=id).update(
                    {
                        "admin_id": admin_id,
                        "user_ids": group.user_ids,
                        "updated_at": int(time.time()),
                    }
                )
                db.commit()
                return self.get_group_by_id(id=id)
        except Exception as e:
            log.exception(e)
            return None

    def get_user_groups_ordered(self, user_id: str) -> list[GroupModel]:
        """获取用户所在的所有权限组，按加入时间排序"""
        try:
            with get_db() as db:
                # 查询用户的活跃组关系，按加入时间排序
                memberships = (
                    db.query(UserGroupMembership)
                    .filter(
                        and_(
                            UserGroupMembership.user_id == user_id,
                            UserGroupMembership.is_active == True,
                        )
                    )
                    .order_by(UserGroupMembership.joined_at.asc())
                    .all()
                )

                # 获取对应的组信息
                groups = []
                for membership in memberships:
                    group = self.get_group_by_id(membership.group_id)
                    if group:
                        groups.append(group)

                return groups
        except Exception as e:
            log.exception(f"Error getting user groups: {e}")
            return []

    def get_user_group(self, user_id: str) -> Optional[GroupModel]:
        """获取用户最早加入的权限组（向后兼容）"""
        groups = self.get_user_groups_ordered(user_id)
        if groups:
            return groups[0]  # 返回最早加入的组
        return None

    def add_user_to_group(self, user_id: str, group_id: str) -> bool:
        """将用户添加到权限组"""
        try:
            with get_db() as db:
                # 检查是否已经在组内
                existing = (
                    db.query(UserGroupMembership)
                    .filter(
                        and_(
                            UserGroupMembership.user_id == user_id,
                            UserGroupMembership.group_id == group_id,
                            UserGroupMembership.is_active == True,
                        )
                    )
                    .first()
                )

                if existing:
                    return True  # 已经在组内

                # 创建新的关系记录
                now = int(time.time())
                membership = UserGroupMembership(
                    id=str(uuid.uuid4()),
                    user_id=user_id,
                    group_id=group_id,
                    joined_at=now,
                    is_active=True,
                    created_at=now,
                    updated_at=now,
                )

                db.add(membership)

                # 同时更新组的 user_ids 字段（向后兼容）
                group = self.get_group_by_id(group_id)
                if group and user_id not in group.user_ids:
                    group.user_ids.append(user_id)
                    db.query(Group).filter_by(id=group_id).update(
                        {
                            "user_ids": group.user_ids,
                            "updated_at": now,
                        }
                    )

                db.commit()
                return True
        except Exception as e:
            log.exception(f"Error adding user to group: {e}")
            return False

    def remove_user_from_group(self, user_id: str, group_id: str) -> bool:
        """将用户从权限组中移除"""
        try:
            with get_db() as db:
                # 标记关系为非活跃
                db.query(UserGroupMembership).filter(
                    and_(
                        UserGroupMembership.user_id == user_id,
                        UserGroupMembership.group_id == group_id,
                        UserGroupMembership.is_active == True,
                    )
                ).update({"is_active": False, "updated_at": int(time.time())})

                # 同时更新组的 user_ids 字段（向后兼容）
                group = self.get_group_by_id(group_id)
                if group and user_id in group.user_ids:
                    group.user_ids.remove(user_id)
                    db.query(Group).filter_by(id=group_id).update(
                        {
                            "user_ids": group.user_ids,
                            "updated_at": int(time.time()),
                        }
                    )

                db.commit()
                return True
        except Exception as e:
            log.exception(f"Error removing user from group: {e}")
            return False

    def ensure_user_in_single_group(self, user_id: str, target_group_id: str) -> bool:
        """确保用户只在一个权限组内（保留用于向后兼容，但现在允许多组）"""
        # 现在允许用户在多个组内，所以这个方法只是确保用户在目标组内
        return self.add_user_to_group(user_id, target_group_id)


Groups = GroupTable()
