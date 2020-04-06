from flask_python_ldap import Entry, Attribute
import ldap
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

    @staticmethod
    def remove_user(ldap_userid,ldap_group, ldap_group_basedn):
        current_app.extensions['ldap'].connection.modify_s(
            f"cn={ldap_group},{ldap_group_basedn}"
            , [(ldap.MOD_DELETE, 'memberUid', [ldap_userid.encode()])])


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
