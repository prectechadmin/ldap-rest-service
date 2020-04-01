import os
from Crypto.Random import get_random_bytes

class Config(object):
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    LDAP_URI = os.environ.get('LDAP_URI',"")
    LDAP_BINDDN = os.environ.get('LDAP_BINDDN',"") # the manger
    LDAP_SECRET = os.environ.get('LDAP_SECRET',"")
    LDAP_AUTH_BASEDN = os.environ.get('LDAP_AUTH_BASEDN',"") # The authenication root DN
    LDAP_AUTH_GROUP_BASEDN = os.environ.get('LDAP_AUTH_GROUP_BASEDN',"") # The authenication root DN
    ENCRYPT_KEY = os.environ.get('ENCRYPT_KEY',"")
    AUTH_TOKEN = os.environ.get('AUTH_TOKEN',"")
    OVIRT_ENGINE_URL =  os.environ.get('OVIRT_ENGINE_URL',"")
    OVIRT_ADMIN_USER = os.environ.get('OVIRT_ADMIN_USER',"")
    OVIRT_ADMIN_PASSWORD = os.environ.get('OVIRT_ADMIN_PASSWORD',"")
    OVIRT_CERT_PATH = os.environ.get('OVIRT_CERT_PATH',"")
    API_SECRET_KEY = os.environ.get('API_SECRET_KEY',"")


class ProductionConfig(Config):

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI',"")

class DevelopmentConfig(Config):
    DEBUG = True
    LDAP_URI = 'ldaps://ldap01.rdng.uk.cloudxtiny.com'
    LDAP_BINDDN = "cn=Manager,dc=cloudxtiny,dc=com"  # the manger
    LDAP_SECRET = "pr3t3chld4p4dm1n"
    LDAP_AUTH_BASEDN = "ou=People,ou=clickitcloud,dc=cloudxtiny,dc=com"  # The authenication root DN
    LDAP_AUTH_GROUP_BASEDN = "ou=Group,ou=clickitcloud,dc=cloudxtiny,dc=com"  # The authenication root DN
    ENCRYPT_KEY = "1757373ef871ebc9dc48e79831816ea7"
    AUTH_TOKEN = "dlkfd-lfkd"
    OVIRT_ENGINE_URL = "https://ovirt-mngnt01.rdng.uk.cloudxtiny.com/ovirt-engine"
    OVIRT_ADMIN_USER = ""
    OVIRT_ADMIN_PASSWORD = ""

class TestingConfig(Config):
    TESTING = True