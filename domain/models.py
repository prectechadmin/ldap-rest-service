from flask import current_app
from sqlalchemy.sql import func
from app import db
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

class ServiceModelMixin:

    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    def dump_object(self):
        return {i.name: getattr(self, i.name) for i in self.__table__.columns}

class ApiUser(ServiceModelMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), unique=False, nullable=False)

    def __repr__(self):
        return '<ApiUser %r>' % self.username

    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

    def generate_auth_token(self, expiration=1800):
        s = Serializer(current_app.config['API_SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['API_SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = ApiUser.query.get(data['id'])
        return user


class User(ServiceModelMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    billing_id = db.Column(db.Integer, unique=True, nullable=False)
    billing_product_id = db.Column(db.Integer, unique=False, nullable=False)
    username = db.Column(db.String(80), unique=False, nullable=False)
    first_name = db.Column(db.String(80), unique=False, nullable=False)
    last_name = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    ldap_group_name = db.Column(db.String(120), unique=False, nullable=False)
    ovirt_user_id = db.Column(db.String(150), unique=False, nullable=False)
    ovirt_auth_domain = db.Column(db.String(120), unique=False, nullable=False)
    encrypted_ovirt_auth_hash = db.Column(db.BLOB, unique=False, nullable=True)
    encrypted_ovirt_auth_iv = db.Column(db.BLOB, unique=False, nullable=True)
    active = db.Column(db.Boolean, default=True, nullable=True)

    def __repr__(self):
        return '<User %r>' % self.username

    @staticmethod
    def encrypt_username_password(username,password):
        cipher = AES.new(current_app.config["ENCRYPT_KEY"].encode("UTF-8"), AES.MODE_CFB, segment_size=128)
        ct_bytes = cipher.encrypt(f"{username} {password}".encode("utf-8"))
        return {"iv":cipher.iv, "ct_bytes":ct_bytes}

    @staticmethod
    def decrypt_username_password(user_auth_hash, encryption_iv):
        cipher = AES.new(
            current_app.config["ENCRYPT_KEY"].encode("UTF-8"), AES.MODE_CFB, segment_size=128, iv=encryption_iv
        )
        username_password = cipher.decrypt(user_auth_hash)
        return username_password.split(" ")

class MetricType(ServiceModelMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.TEXT, unique=False, nullable=True)
    unit_price = db.Column(db.DECIMAL(precision=10, scale=4), unique=False, nullable=True, default=0.00)
    volume_per_unit = db.Column(db.Integer, unique=False, nullable=True, default=1)

    def __repr__(self):
        return '<MetricType %r>' % self.name

class Metric(ServiceModelMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id =  db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_name = db.Column(db.String(50), unique=False, nullable=False)
    description = db.Column(db.String(150), unique=False, nullable=True)
    metric_type_id = db.Column(db.Integer, db.ForeignKey('metric_type.id'), nullable=False)
    metric_value = db.Column(db.DECIMAL(precision=10, scale=4), unique=False, nullable=False, default=0.00)

    metric_type = db.relationship('MetricType',
                           backref=db.backref('metric_type', lazy=True))
    user = db.relationship('User',
                           backref=db.backref('user', lazy=True))
    def __repr__(self):
        return '<Metric %r>' % self.service_name