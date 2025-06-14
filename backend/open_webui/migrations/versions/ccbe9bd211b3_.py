"""empty message

Revision ID: ccbe9bd211b3
Revises: add_subscription_credits_table, ca00a851d4d9
Create Date: 2025-06-14 18:21:40.041222

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import open_webui.internal.db


# revision identifiers, used by Alembic.
revision: str = "ccbe9bd211b3"
down_revision: Union[str, None] = ("add_subscription_credits_table", "ca00a851d4d9")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
