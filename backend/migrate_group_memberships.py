#!/usr/bin/env python3
"""
数据迁移脚本：将现有的用户组关系迁移到新的用户组关系表

使用方法：
python migrate_group_memberships.py

这个脚本会：
1. 读取现有 group 表中的 user_ids 字段
2. 为每个用户-组关系在 user_group_membership 表中创建记录
3. 设置加入时间为组的创建时间
"""

import uuid
import time
import sys
import os

# 添加项目根目录到 Python 路径
sys.path.append(os.path.join(os.path.dirname(__file__)))

from open_webui.internal.db import get_db
from open_webui.models.groups import Group, UserGroupMembership
from sqlalchemy import text


def migrate_group_memberships():
    """迁移现有的用户组关系到新表"""

    print("开始迁移用户组关系...")

    try:
        with get_db() as db:
            # 检查新表是否存在
            result = db.execute(
                text(
                    """
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='user_group_membership'
            """
                )
            ).fetchone()

            if not result:
                print("错误：user_group_membership 表不存在，请先运行数据库迁移")
                return False

            # 获取所有有用户的组
            groups = db.query(Group).filter(Group.user_ids.isnot(None)).all()

            migrated_count = 0
            skipped_count = 0

            for group in groups:
                if not group.user_ids:
                    continue

                print(f"处理组: {group.name} (ID: {group.id})")

                # 为组中的每个用户创建关系记录
                for user_id in group.user_ids:
                    if not user_id:
                        continue

                    # 检查是否已经存在记录
                    existing = (
                        db.query(UserGroupMembership)
                        .filter(
                            UserGroupMembership.user_id == user_id,
                            UserGroupMembership.group_id == group.id,
                            UserGroupMembership.is_active == True,
                        )
                        .first()
                    )

                    if existing:
                        print(f"  跳过用户 {user_id}：关系记录已存在")
                        skipped_count += 1
                        continue

                    # 创建新的关系记录
                    membership = UserGroupMembership(
                        id=str(uuid.uuid4()),
                        user_id=user_id,
                        group_id=group.id,
                        joined_at=group.created_at,  # 使用组的创建时间作为加入时间
                        is_active=True,
                        created_at=int(time.time()),
                        updated_at=int(time.time()),
                    )

                    db.add(membership)
                    migrated_count += 1
                    print(f"  为用户 {user_id} 创建关系记录")

            # 提交事务
            db.commit()

            print(f"\n迁移完成！")
            print(f"新创建的关系记录：{migrated_count}")
            print(f"跳过的记录（已存在）：{skipped_count}")

            return True

    except Exception as e:
        print(f"迁移失败：{str(e)}")
        return False


def verify_migration():
    """验证迁移结果"""

    print("\n验证迁移结果...")

    try:
        with get_db() as db:
            # 统计原始数据
            groups_with_users = db.query(Group).filter(Group.user_ids.isnot(None)).all()
            original_relationships = 0

            for group in groups_with_users:
                if group.user_ids:
                    original_relationships += len(
                        [uid for uid in group.user_ids if uid]
                    )

            # 统计新表中的活跃关系
            new_relationships = (
                db.query(UserGroupMembership)
                .filter(UserGroupMembership.is_active == True)
                .count()
            )

            print(f"原始用户-组关系数：{original_relationships}")
            print(f"新表中活跃关系数：{new_relationships}")

            if original_relationships == new_relationships:
                print("✅ 验证通过：数据迁移成功")
                return True
            else:
                print("❌ 验证失败：数据不匹配")
                return False

    except Exception as e:
        print(f"验证失败：{str(e)}")
        return False


if __name__ == "__main__":
    print("用户组关系数据迁移工具")
    print("=" * 50)

    # 执行迁移
    success = migrate_group_memberships()

    if success:
        # 验证迁移结果
        verify_migration()

        print("\n" + "=" * 50)
        print("迁移完成！")
        print("\n注意事项：")
        print("1. 现在用户可以加入多个企业组")
        print("2. 扣积分时会按加入时间顺序优先扣除最早加入组的管理员积分")
        print("3. 可以使用新的 API 来管理用户组关系：")
        print("   - POST /api/v1/groups/id/{group_id}/add-user/{user_id}")
        print("   - POST /api/v1/groups/id/{group_id}/remove-user/{user_id}")
        print("   - GET /api/v1/groups/user/{user_id}/groups")
    else:
        print("\n❌ 迁移失败，请检查错误信息并重试")
        sys.exit(1)
