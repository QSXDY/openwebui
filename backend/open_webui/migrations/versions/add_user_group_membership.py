"""Add user group membership table for multiple group support

Revision ID: add_user_group_membership
Revises: 922e7a387820
Create Date: 2024-12-19 10:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

revision = "add_user_group_membership"
down_revision = "922e7a387820"
branch_labels = None
depends_on = None


def upgrade():
    # 创建用户-组关系表
    op.create_table(
        "user_group_membership",
        sa.Column("id", sa.Text(), nullable=False, primary_key=True),
        sa.Column("user_id", sa.Text(), nullable=False, index=True),
        sa.Column("group_id", sa.Text(), nullable=False, index=True),
        sa.Column("joined_at", sa.BigInteger(), nullable=False),  # 加入时间
        sa.Column("is_active", sa.Boolean(), nullable=False, default=True),  # 是否活跃
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
    )

    # 添加联合唯一索引，确保用户在同一组内只有一条活跃记录
    op.create_index(
        "idx_user_group_unique_active",
        "user_group_membership",
        ["user_id", "group_id", "is_active"],
        unique=True,
        postgresql_where=sa.text("is_active = true"),
    )

    # 添加外键约束（如果需要的话）
    op.create_foreign_key(
        "fk_user_group_membership_group_id",
        "user_group_membership",
        "group",
        ["group_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade():
    op.drop_table("user_group_membership")
