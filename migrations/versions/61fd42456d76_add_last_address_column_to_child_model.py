"""Add last_address column to Child model

Revision ID: 61fd42456d76
Revises: 8a9499212c90
Create Date: 2024-12-30 20:24:44.356281

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '61fd42456d76'
down_revision = '8a9499212c90'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('child', schema=None) as batch_op:
        batch_op.add_column(sa.Column('last_address', sa.String(length=200), nullable=True))
        batch_op.alter_column('name',
               existing_type=sa.VARCHAR(length=80),
               type_=sa.String(length=100),
               existing_nullable=False)
        batch_op.alter_column('device_id',
               existing_type=sa.VARCHAR(length=120),
               type_=sa.String(length=100),
               existing_nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('child', schema=None) as batch_op:
        batch_op.alter_column('device_id',
               existing_type=sa.String(length=100),
               type_=sa.VARCHAR(length=120),
               existing_nullable=False)
        batch_op.alter_column('name',
               existing_type=sa.String(length=100),
               type_=sa.VARCHAR(length=80),
               existing_nullable=False)
        batch_op.drop_column('last_address')

    # ### end Alembic commands ###
