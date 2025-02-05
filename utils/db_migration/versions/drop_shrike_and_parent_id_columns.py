# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Drop shrike and Parent ID Columns

Revision ID: a6a2be295f9e
Revises: c2bd0eb5e69d
Create Date: 2025-01-27 15:36:22.144546

"""

# revision identifiers, used by Alembic.
revision = "a6a2be295f9e"
down_revision = "c2bd0eb5e69d"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_column("tasks", "shrike_url")
    op.drop_column("tasks", "shrike_refer")
    op.drop_column("tasks", "shrike_msg")
    op.drop_column("tasks", "shrike_sid")
    op.drop_column("tasks", "parent_id")


def downgrade():
    op.add_column("tasks", sa.Column("shrike_url", sa.String(length=4096), nullable=True))
    op.add_column("tasks", sa.Column("shrike_refer", sa.String(length=4096), nullable=True))
    op.add_column("tasks", sa.Column("shrike_msg", sa.String(length=4096), nullable=True))
    op.add_column("tasks", sa.Column("shrike_sid", sa.Integer(), nullable=True))
    op.add_column("tasks", sa.Column("parent_id", sa.Integer(), nullable=True))
