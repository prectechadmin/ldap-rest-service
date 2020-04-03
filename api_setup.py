import os
from app import db
from domain.models import ApiUser
db.drop_all()
db.create_all()