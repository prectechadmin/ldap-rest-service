from flask import current_app
from app import db
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)


class ApiUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), unique=False, nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return '<ApiUser %r>' % self.username

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
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
        user = User.query.get(data['id'])
        return user

class ApiToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('api_user.id'), nullable=False)
    token = db.Column(db.String(50), unique=False, nullable=False)
    user = db.relationship('ApiUser',
                                  backref=db.backref('api_user', lazy=True))

    def __repr__(self):
        return '<apiToken %r>' % self.token

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    billing_id = db.Column(db.Integer, unique=True, nullable=False)
    billing_product_id = db.Column(db.Integer, unique=False, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    ldap_group_name = db.Column(db.String(120), unique=False, nullable=False)
    ovirt_user_id = db.Column(db.String(150), unique=False, nullable=False)
    ovirt_auth_domain = db.Column(db.String(120), unique=True, nullable=False)
    encrypted_ovirt_auth_hash = db.Column(db.BLOB, unique=True, nullable=True)
    encrypted_ovirt_auth_iv = db.Column(db.BLOB, unique=True, nullable=True)
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

    @staticmethod
    def encrypt_username_password(username,password,user_auth_domain):
        cipher = AES.new(current_app.config["ENCRYPT_KEY"].encode("UTF-8"), AES.MODE_CFB, segment_size=128)
        ct_bytes = cipher.encrypt(f"{username} {password}".encode("utf-8"))
        return {"iv":cipher.iv, "ct_bytes":ct_bytes}

    @staticmethod
    def decrypt_username_password(user_auth_domain_hash, encryption_iv):
        cipher = AES.new(
            current_app.config["ENCRYPT_KEY"].encode("UTF-8"), AES.MODE_CFB, segment_size=128, iv=encryption_iv
        )
        username_password = cipher.decrypt(user_auth_domain_hash)
        return username_password.split(" ")


class Metric(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id =  db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_name = db.Column(db.String(50), unique=False, nullable=False)
    description = db.Column(db.String(150), unique=False, nullable=True)
    metric_type_id = db.Column(db.Integer, db.ForeignKey('metrics_type.id'), nullable=False)
    metric_value = db.Column(db.DECIMAL, unique=False, nullable=False, default=0.00)
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    metric_type = db.relationship('MetricType',
                           backref=db.backref('metric', lazy=True))
    user = db.relationship('User',
                           backref=db.backref('user', lazy=True))
    def __repr__(self):
        return '<Metrics %r>' % self.service_name

class MetricsType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.TEXT, unique=False, nullable=True)
    unit_price = db.Column(db.DECIMAL, unique=False, nullable=False, default=0.00)
    volume_per_unit = db.Column(db.Integer, unique=False, nullable=False, default=1)
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return '<MetricsType %r>' % self.name