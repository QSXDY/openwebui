"""merge branches

Revision ID: 3c526075dc91
Revises: b1a2c3d4e5f6, ccbe9bd211b3
Create Date: 2025-06-21 23:28:05.743666

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import open_webui.internal.db


# revision identifiers, used by Alembic.
revision: str = "3c526075dc91"
down_revision: Union[str, None] = ("b1a2c3d4e5f6", "ccbe9bd211b3")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
