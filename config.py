import os
from Crypto.Random import get_random_bytes

class Config(object):
    DEBUG = False
    TESTING = False
    DATABASE_URI = 'sqlite:///:memory:'
    LDAP_URI = os.environ.get('LDAP_URI',"")
    LDAP_BINDDN = os.environ.get('LDAP_BINDDN',"") # the manger
    LDAP_SECRET = os.environ.get('LDAP_SECRET',"")
    LDAP_AUTH_BASEDN = os.environ.get('LDAP_AUTH_BASEDN',"") # The authenication root DN
    LDAP_AUTH_GROUP_BASEDN = os.environ.get('LDAP_AUTH_GROUP_BASEDN',"") # The authenication root DN
    ENCRYPT_KEY = os.environ.get('ENCRYPT_KEY',"")
    AUTH_TOKEN = os.environ.get('AUTH_TOKEN',"")
    OVIRT_ENGINE_URL =  os.environ.get('OVIRT_ENGINE_URL',"")


class ProductionConfig(Config):
    pass
    #DATABASE_URI = f"mysql+pymysql://" \
    #               f"{os.environ['MYSQL_USER']}:{os.environ['MYSQL_PASS']}@" \
    #               f"{os.environ['MYSQL_HOST']}/{os.environ['MYSQL_DATABASE']}"

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

class TestingConfig(Config):
    TESTING = True