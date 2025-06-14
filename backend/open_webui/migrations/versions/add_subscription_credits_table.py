"""
添加套餐积分记录表
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

# revision identifiers
revision = "add_subscription_credits_table"
down_revision = None  # 设置为上一个迁移的revision
branch_labels = None
depends_on = None


def upgrade():
    # 创建套餐积分记录表
    op.create_table(
        "subscription_credits",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("subscription_id", sa.String(), nullable=True),
        sa.Column("plan_id", sa.String(), nullable=True),
        sa.Column("total_credits", sa.BigInteger(), default=0),
        sa.Column("remaining_credits", sa.BigInteger(), default=0),
        sa.Column("consumed_credits", sa.BigInteger(), default=0),
        sa.Column("start_date", sa.BigInteger(), nullable=False),
        sa.Column("end_date", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(20), default="active"),
        sa.Column("created_at", sa.BigInteger(), nullable=True),
        sa.Column("updated_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscription_subscriptions.id"]),
        sa.ForeignKeyConstraint(["plan_id"], ["subscription_plans.id"]),
    )

    # 创建索引
    op.create_index(
        "ix_subscription_credits_user_id", "subscription_credits", ["user_id"]
    )
    op.create_index(
        "ix_subscription_credits_status", "subscription_credits", ["status"]
    )
    op.create_index(
        "ix_subscription_credits_end_date", "subscription_credits", ["end_date"]
    )


def downgrade():
    op.drop_table("subscription_credits")
