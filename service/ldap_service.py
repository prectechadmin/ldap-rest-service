from flask_python_ldap import Entry, Attribute


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

