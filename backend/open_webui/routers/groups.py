import os
from pathlib import Path
from typing import Optional
import logging

from open_webui.models.users import Users
from open_webui.models.groups import (
    Groups,
    GroupForm,
    GroupUpdateForm,
    GroupResponse,
    GroupAdminForm,
)
from open_webui.models.credits import Credits

from open_webui.config import CACHE_DIR
from open_webui.constants import ERROR_MESSAGES
from fastapi import APIRouter, Depends, HTTPException, Request, status

from open_webui.utils.auth import get_admin_user, get_verified_user
from open_webui.env import SRC_LOG_LEVELS


log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MAIN"])

router = APIRouter()

############################
# GetFunctions
############################


@router.get("/", response_model=list[GroupResponse])
async def get_groups(user=Depends(get_verified_user)):
    if user.role == "admin":
        return Groups.get_groups()
    else:
        return Groups.get_groups_by_member_id(user.id)


############################
# CreateNewGroup
############################


@router.post("/create", response_model=Optional[GroupResponse])
async def create_new_group(form_data: GroupForm, user=Depends(get_admin_user)):
    try:
        group = Groups.insert_new_group(user.id, form_data)
        if group:
            return group
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error creating group"),
            )
    except Exception as e:
        log.exception(f"Error creating a new group: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )


############################
# GetGroupById
############################


@router.get("/id/{id}", response_model=Optional[GroupResponse])
async def get_group_by_id(id: str, user=Depends(get_admin_user)):
    group = Groups.get_group_by_id(id)
    if group:
        return group
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


############################
# SetGroupAdmin
############################


@router.post("/id/{id}/set-admin", response_model=Optional[GroupResponse])
async def set_group_admin(
    id: str, form_data: GroupAdminForm, user=Depends(get_admin_user)
):
    """设置权限组管理员"""
    try:
        # 验证管理员ID是否有效
        admin_user = Users.get_user_by_id(form_data.admin_id)
        if not admin_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Invalid admin user ID"),
            )

        # 设置管理员并确保该用户在这个组内
        group = Groups.set_group_admin_by_id(id, form_data.admin_id)
        Groups.add_user_to_group(form_data.admin_id, id)

        if group:
            return group
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error setting group admin"),
            )
    except Exception as e:
        log.exception(f"Error setting group admin for group {id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )


############################
# GetGroupAdminCredit
############################


@router.get("/admin-credit", response_model=dict)
async def get_group_admin_credit(user=Depends(get_verified_user)):
    """获取用户所在权限组管理员的积分（按加入顺序优先）"""
    try:
        # 获取用户所在的所有权限组（按加入时间排序）
        groups = Groups.get_user_groups_ordered(user.id)

        # 如果用户不在任何组内
        if not groups:
            user_credit = Credits.get_credit_by_user_id(user.id)
            return {
                "user_credit": user_credit.credit if user_credit else 0,
                "admin_credit": None,
                "admin_id": None,
                "admin_name": None,
                "group_id": None,
                "group_name": None,
                "groups": [],
            }

        # 找到第一个有管理员且管理员有积分的组
        primary_group = None
        admin_user = None
        admin_credit = None

        for group in groups:
            if group.admin_id and group.admin_id != user.id:
                temp_admin_credit = Credits.get_credit_by_user_id(group.admin_id)
                if temp_admin_credit and float(temp_admin_credit.credit) > 0:
                    primary_group = group
                    admin_user = Users.get_user_by_id(group.admin_id)
                    admin_credit = temp_admin_credit
                    break

        # 如果没有找到有效的管理员积分，使用第一个组
        if not primary_group and groups:
            primary_group = groups[0]
            if primary_group.admin_id:
                admin_user = Users.get_user_by_id(primary_group.admin_id)
                admin_credit = Credits.get_credit_by_user_id(primary_group.admin_id)

        user_credit = Credits.get_credit_by_user_id(user.id)

        return {
            "user_credit": user_credit.credit if user_credit else 0,
            "admin_credit": admin_credit.credit if admin_credit else 0,
            "admin_id": admin_user.id if admin_user else None,
            "admin_name": admin_user.name if admin_user else None,
            "group_id": primary_group.id if primary_group else None,
            "group_name": primary_group.name if primary_group else None,
            "groups": [
                {
                    "id": group.id,
                    "name": group.name,
                    "admin_id": group.admin_id,
                    "admin_name": (
                        Users.get_user_by_id(group.admin_id).name
                        if group.admin_id and Users.get_user_by_id(group.admin_id)
                        else None
                    ),
                    "admin_credit": (
                        Credits.get_credit_by_user_id(group.admin_id).credit
                        if group.admin_id
                        and Credits.get_credit_by_user_id(group.admin_id)
                        else 0
                    ),
                }
                for group in groups
            ],
        }
    except Exception as e:
        log.exception(f"Error getting group admin credit: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )


############################
# UpdateGroupById - 修改现有方法确保用户只在一个组内
############################


@router.post("/id/{id}/update", response_model=Optional[GroupResponse])
async def update_group_by_id(
    id: str, form_data: GroupUpdateForm, user=Depends(get_admin_user)
):
    try:
        if form_data.user_ids:
            form_data.user_ids = Users.get_valid_user_ids(form_data.user_ids)

            # 将每个用户添加到这个组内（允许多组）
            for user_id in form_data.user_ids:
                Groups.add_user_to_group(user_id, id)

        group = Groups.update_group_by_id(id, form_data)
        if group:
            return group
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error updating group"),
            )
    except Exception as e:
        log.exception(f"Error updating group {id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )


############################
# DeleteGroupById
############################


@router.delete("/id/{id}/delete", response_model=bool)
async def delete_group_by_id(id: str, user=Depends(get_admin_user)):
    try:
        result = Groups.delete_group_by_id(id)
        if result:
            return result
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error deleting group"),
            )
    except Exception as e:
        log.exception(f"Error deleting group {id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )


############################
# 用户组管理 API
############################


@router.post("/id/{group_id}/add-user/{user_id}", response_model=dict)
async def add_user_to_group(
    group_id: str, user_id: str, admin_user=Depends(get_admin_user)
):
    """将用户添加到权限组"""
    try:
        # 验证用户ID是否有效
        user = Users.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Invalid user ID"),
            )

        # 验证组是否存在
        group = Groups.get_group_by_id(group_id)
        if not group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ERROR_MESSAGES.DEFAULT("Group not found"),
            )

        success = Groups.add_user_to_group(user_id, group_id)
        if success:
            return {
                "success": True,
                "message": f"用户 {user.name} 已添加到组 {group.name}",
                "user_id": user_id,
                "group_id": group_id,
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Failed to add user to group"),
            )
    except Exception as e:
        log.exception(f"Error adding user {user_id} to group {group_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )


@router.post("/id/{group_id}/remove-user/{user_id}", response_model=dict)
async def remove_user_from_group(
    group_id: str, user_id: str, admin_user=Depends(get_admin_user)
):
    """将用户从权限组中移除"""
    try:
        # 验证用户ID是否有效
        user = Users.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Invalid user ID"),
            )

        # 验证组是否存在
        group = Groups.get_group_by_id(group_id)
        if not group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ERROR_MESSAGES.DEFAULT("Group not found"),
            )

        success = Groups.remove_user_from_group(user_id, group_id)
        if success:
            return {
                "success": True,
                "message": f"用户 {user.name} 已从组 {group.name} 中移除",
                "user_id": user_id,
                "group_id": group_id,
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Failed to remove user from group"),
            )
    except Exception as e:
        log.exception(f"Error removing user {user_id} from group {group_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )


@router.get("/user/{user_id}/groups", response_model=list)
async def get_user_groups(user_id: str, admin_user=Depends(get_admin_user)):
    """获取用户所在的所有权限组（按加入时间排序）"""
    try:
        # 验证用户ID是否有效
        user = Users.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Invalid user ID"),
            )

        groups = Groups.get_user_groups_ordered(user_id)
        return [
            {
                "id": group.id,
                "name": group.name,
                "description": group.description,
                "admin_id": group.admin_id,
                "created_at": group.created_at,
                "updated_at": group.updated_at,
            }
            for group in groups
        ]
    except Exception as e:
        log.exception(f"Error getting groups for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )
