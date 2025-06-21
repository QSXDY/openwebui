"""add user bindings and login methods

Revision ID: b1a2c3d4e5f6
Revises: a959f8a63245
Create Date: 2025-06-21 18:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from open_webui.internal.db import JSONField

# revision identifiers, used by Alembic.
revision: str = "b1a2c3d4e5f6"
down_revision: Union[str, None] = "a959f8a63245"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 创建用户绑定表，用于管理不同登录方式之间的绑定关系
    op.create_table(
        "user_bindings",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("primary_user_id", sa.String(), nullable=False, comment="主用户ID"),
        sa.Column("bound_user_id", sa.String(), nullable=False, comment="绑定的用户ID"),
        sa.Column(
            "primary_login_type",
            sa.String(20),
            nullable=False,
            comment="主登录方式: email, phone, wechat",
        ),
        sa.Column(
            "bound_login_type",
            sa.String(20),
            nullable=False,
            comment="绑定的登录方式: email, phone, wechat",
        ),
        sa.Column(
            "binding_status",
            sa.String(20),
            nullable=False,
            default="active",
            comment="绑定状态: active, inactive",
        ),
        sa.Column(
            "binding_data", JSONField(), nullable=True, comment="绑定相关的额外数据"
        ),
        sa.Column("created_at", sa.BigInteger(), nullable=True),
        sa.Column("updated_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["primary_user_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["bound_user_id"], ["user.id"]),
        sa.UniqueConstraint(
            "primary_user_id", "bound_user_id", name="uq_user_binding_pair"
        ),
    )

    # 创建索引
    op.create_index(
        "ix_user_bindings_primary_user_id", "user_bindings", ["primary_user_id"]
    )
    op.create_index(
        "ix_user_bindings_bound_user_id", "user_bindings", ["bound_user_id"]
    )
    op.create_index(
        "ix_user_bindings_login_types",
        "user_bindings",
        ["primary_login_type", "bound_login_type"],
    )
    op.create_index("ix_user_bindings_status", "user_bindings", ["binding_status"])

    # 为auth表添加登录方式字段
    op.add_column(
        "auth",
        sa.Column(
            "login_type",
            sa.String(20),
            nullable=True,
            default="email",
            comment="登录方式: email, phone, wechat",
        ),
    )
    op.add_column(
        "auth",
        sa.Column(
            "external_id",
            sa.String(),
            nullable=True,
            comment="外部系统ID（如微信openid）",
        ),
    )
    op.add_column(
        "auth",
        sa.Column("phone_number", sa.String(20), nullable=True, comment="手机号"),
    )
    op.add_column(
        "auth",
        sa.Column("wechat_openid", sa.String(), nullable=True, comment="微信openid"),
    )
    op.add_column(
        "auth",
        sa.Column("wechat_unionid", sa.String(), nullable=True, comment="微信unionid"),
    )
    op.add_column(
        "auth",
        sa.Column(
            "auth_metadata", JSONField(), nullable=True, comment="认证相关的元数据"
        ),
    )

    # 为user表添加绑定相关字段
    op.add_column(
        "user",
        sa.Column(
            "primary_login_type",
            sa.String(20),
            nullable=True,
            default="email",
            comment="主要登录方式",
        ),
    )
    op.add_column(
        "user",
        sa.Column(
            "available_login_types",
            sa.String(),
            nullable=True,
            comment="可用的登录方式，逗号分隔",
        ),
    )
    op.add_column(
        "user",
        sa.Column("phone_number", sa.String(20), nullable=True, comment="绑定的手机号"),
    )
    op.add_column(
        "user",
        sa.Column(
            "wechat_openid", sa.String(), nullable=True, comment="绑定的微信openid"
        ),
    )
    op.add_column(
        "user",
        sa.Column("wechat_nickname", sa.String(), nullable=True, comment="微信昵称"),
    )
    op.add_column(
        "user",
        sa.Column(
            "binding_status",
            JSONField(),
            nullable=True,
            comment="各种登录方式的绑定状态",
        ),
    )

    # 创建auth表的索引
    op.create_index("ix_auth_login_type", "auth", ["login_type"])
    op.create_index("ix_auth_phone_number", "auth", ["phone_number"])
    op.create_index("ix_auth_wechat_openid", "auth", ["wechat_openid"])
    op.create_index("ix_auth_external_id", "auth", ["external_id"])

    # 创建user表的索引
    op.create_index("ix_user_phone_number", "user", ["phone_number"])
    op.create_index("ix_user_wechat_openid", "user", ["wechat_openid"])
    op.create_index("ix_user_primary_login_type", "user", ["primary_login_type"])

    # 更新现有数据的默认值
    op.execute("UPDATE auth SET login_type = 'email' WHERE login_type IS NULL")
    op.execute(
        "UPDATE user SET primary_login_type = 'email' WHERE primary_login_type IS NULL"
    )
    op.execute(
        "UPDATE user SET available_login_types = 'email' WHERE available_login_types IS NULL"
    )


def downgrade() -> None:
    # 删除索引
    op.drop_index("ix_user_primary_login_type", "user")
    op.drop_index("ix_user_wechat_openid", "user")
    op.drop_index("ix_user_phone_number", "user")
    op.drop_index("ix_auth_external_id", "auth")
    op.drop_index("ix_auth_wechat_openid", "auth")
    op.drop_index("ix_auth_phone_number", "auth")
    op.drop_index("ix_auth_login_type", "auth")

    # 删除user表的字段
    op.drop_column("user", "binding_status")
    op.drop_column("user", "wechat_nickname")
    op.drop_column("user", "wechat_openid")
    op.drop_column("user", "phone_number")
    op.drop_column("user", "available_login_types")
    op.drop_column("user", "primary_login_type")

    # 删除auth表的字段
    op.drop_column("auth", "auth_metadata")
    op.drop_column("auth", "wechat_unionid")
    op.drop_column("auth", "wechat_openid")
    op.drop_column("auth", "phone_number")
    op.drop_column("auth", "external_id")
    op.drop_column("auth", "login_type")

    # 删除user_bindings表
    op.drop_table("user_bindings")
