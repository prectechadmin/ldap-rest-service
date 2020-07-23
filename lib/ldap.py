from flask import current_app, _app_ctx_stack
from flask_python_ldap import LDAP
import ldap


class cLDAP(LDAP):

    def __init__(self, app=None):
        LDAP.__init__(self, app)
        self.logger = app.logger

    def connect(self):
        uri = current_app.config['LDAP_URI']
        conn = ldap.initialize(uri)
        if (uri.startswith('ldaps:')):
            conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
            conn.set_option(ldap.OPT_X_TLS_NEWCTX,0)
        conn.simple_bind_s(current_app.config['LDAP_BINDDN'], current_app.config['LDAP_SECRET'])
        return conn
