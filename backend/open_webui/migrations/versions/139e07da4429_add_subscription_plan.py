"""add_subscription_plan

Revision ID: 139e07da4429
Revises: 9f0c9cd09105
Create Date: 2025-05-22 18:58:28.862716

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import open_webui.internal.db


# revision identifiers, used by Alembic.
revision: str = "139e07da4429"
down_revision: Union[str, None] = "9f0c9cd09105"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 创建套餐表
    op.create_table(
        "subscription_plans",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column(
            "price", sa.Numeric(precision=24, scale=12), nullable=True, default=0
        ),
        sa.Column("features", sa.JSON(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("duration", sa.BigInteger(), nullable=True, default=30),
        sa.Column("credits", sa.BigInteger(), nullable=True, default=0),
        sa.Column("is_active", sa.Boolean(), nullable=True, default=True),
        sa.Column("created_at", sa.BigInteger(), nullable=True),
        sa.Column("updated_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # 创建订阅表
    op.create_table(
        "subscription_subscriptions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("plan_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(20), nullable=True, default="active"),
        sa.Column("start_date", sa.BigInteger(), nullable=False),
        sa.Column("end_date", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=True),
        sa.Column("updated_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["plan_id"], ["subscription_plans.id"]),
        sa.Index("ix_subscription_subscriptions_user_id", "user_id"),
    )

    # 创建兑换码表
    op.create_table(
        "subscription_redeem_codes",
        sa.Column("code", sa.String(), nullable=False),
        sa.Column("plan_id", sa.String(), nullable=True),
        sa.Column("duration_days", sa.BigInteger(), nullable=True, default=30),
        sa.Column("is_used", sa.Boolean(), nullable=True, default=False),
        sa.Column("used_by", sa.String(), nullable=True),
        sa.Column("used_at", sa.BigInteger(), nullable=True),
        sa.Column("expires_at", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("code"),
        sa.ForeignKeyConstraint(["plan_id"], ["subscription_plans.id"]),
    )

    # 创建支付记录表
    op.create_table(
        "subscription_payments",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("plan_id", sa.String(), nullable=True),
        sa.Column(
            "amount", sa.Numeric(precision=24, scale=12), nullable=True, default=0
        ),
        sa.Column("payment_method", sa.String(50), nullable=True, default="lantupay"),
        sa.Column("transaction_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(20), nullable=True, default="pending"),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("payment_type", sa.String(20), nullable=True, default="subscription"),
        sa.Column("credits", sa.BigInteger(), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=True),
        sa.Column("updated_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["plan_id"], ["subscription_plans.id"]),
        sa.Index("ix_subscription_payments_user_id", "user_id"),
    )


def downgrade() -> None:
    op.drop_table("subscription_payments")
    op.drop_table("subscription_redeem_codes")
    op.drop_table("subscription_subscriptions")
    op.drop_table("subscription_plans")
