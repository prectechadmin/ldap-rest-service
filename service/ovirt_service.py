import requests,os
from flask import current_app

class AdminToken:
    def __init__(self, access_token,token_type,scope,timeout=0):
        self.access_token = access_token
        self.token_type = token_type
        self.scope = scope
        self.timeout = 0

class OvirtEngineService:

    def __init__(self):
        self.ovirt_engine_host = os.application.config["OVIRT_ENGINE_URL"]
        self.admin_token = self.get_admin_token()

    def get_admin_token(self):
        # get an administrator auth token
        pass

    def login_and_get_user_id(self, username,password):
        # login as a user and get their user id
        pass

    def apply_UserRole_Permission(self,userid):
        pass