"""merge 139e07da4429 and add_subscription_credit_type

Revision ID: ca00a851d4d9
Revises: 139e07da4429, add_subscription_credit_type
Create Date: 2025-06-14 15:58:40.873442

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import open_webui.internal.db


# revision identifiers, used by Alembic.
revision: str = "ca00a851d4d9"
down_revision: Union[str, None] = ("139e07da4429", "add_subscription_credit_type")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
