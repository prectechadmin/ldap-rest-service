from flask_python_ldap import Entry, Attribute
import json
import os,sys
from base64 import urlsafe_b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from flask import current_app

class LdapEntry:

    @classmethod
    def set_basedn(cls, base_dn):
        cls.base_dn = base_dn
        return cls


class LdapGroup(Entry,LdapEntry):
    entry_rdn = 'cn'
    object_classes = ['top', 'posixGroup']
    group_name = Attribute('cn')
    gid = Attribute('gidNumber')
    members = Attribute('memberuid', is_list=True)


class LdapUser(Entry,LdapEntry):

    entry_rdn = 'uid'
    object_classes = ['top', 'posixAccount', 'inetOrgPerson']
    # inetOrgPerson
    surname = Attribute('sn')
    firstname = Attribute('givenName')
    email = Attribute('mail', is_list=True)
    username = Attribute('uid')
    userid =  Attribute('uidNumber')
    password = Attribute('userPassword')
    name = Attribute('cn')
    gid = Attribute('gidNumber')
    home = Attribute('homeDirectory')

    def encrypt_username_password(self):
        cipher = AES.new(current_app.config["ENCRYPT_KEY"].encode("UTF-8"), AES.MODE_CFB, segment_size=128)
        ct_bytes = cipher.encrypt(f"{self.username} {self.password}".encode("utf-8"))
        iv = urlsafe_b64encode(cipher.iv).decode('utf-8')
        ct = urlsafe_b64encode(ct_bytes).decode('utf-8')
        return json.dumps({'java_ciphertext': urlsafe_b64encode(cipher.iv + ct_bytes).decode('utf-8')})

