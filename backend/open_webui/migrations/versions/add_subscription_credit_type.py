"""
添加套餐积分类型字段和套餐积分余额字段
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

# revision identifiers
revision = "add_subscription_credit_type"
down_revision = None  # 设置为上一个迁移的revision
branch_labels = None
depends_on = None


def upgrade():

    # 为套餐表添加是否一次性发放字段
    op.add_column(
        "subscription_plans", sa.Column("grant_type", sa.String(20), default="monthly")
    )

    # 更新现有数据
    connection = op.get_bind()
    connection.execute(
        text(
            "UPDATE subscription_plans SET grant_type = 'monthly' WHERE grant_type IS NULL"
        )
    )


def downgrade():
    op.drop_column("subscription_plans", "grant_type")
