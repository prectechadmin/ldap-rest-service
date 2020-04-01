from flask import current_app
import logging
import ovirtsdk4 as sdk
import ovirtsdk4.types as types

class OvirtEngineService:

    def __init__(self, username=None, password=None,domain="internal"):
        self.is_admin = False
        self.domain = domain
        if (username):
            self.username = username
            self.password = password
        else:
            self.username = current_app.config["OVIRT_ADMIN_USER"]
            self.password = current_app.config["OVIRT_ADMIN_PASSWORD"]
            self.is_admin = True
            self.domain ="internal"

        self.connection = sdk.Connection(
            url=current_app.config["OVIRT_ENGINE_URL"],
            username=f"{self.username}@{self.domain}",
            password=self.password,
            ca_file=current_app.config["OVIRT_CERT_PATH"],
            debug=current_app.config["DEBUG"],
            log=logging.getLogger("OvirtService"),
        )
        self.user = self.connection.system_service().users_service().list(
            search=f'name={self.username}&domain={self.domain}'
        )[0]


    def __del__(self):
        self.connection.close()

    def getUserDetailsById(self, userid):
        # login as a user and get their user id
        if self.is_admin:
            return self.connection.system_service().users_service(userid)
        else:
            raise RuntimeError("Sorry only an admin user is allowed to perform this operation")

    def getUserDetailsByUsername(self, username, auth_domain):

        if self.is_admin:
            return self.connection.system_service().users_service().list(
                search=f'name={username}&domain={auth_domain}'
            )[0]
        else:
            raise RuntimeError("Sorry only an admin user is allowed to perform this operation")

    def deleteUserAccount(self, userid):
        if self.is_admin:
            return self.connection.system_service().users_service(userid).remove()
        else:
            raise RuntimeError("Sorry only an admin user is allowed to perform this operation")

    def terminateUserServices(self, userid):
        # get user vms
        user_vms = self.connection.system_service().vms_service().list()
        # for each terminate
        for avm in user_vms:
            if self.connection.system_service().vms_service(avm.id).shutdown():
                self.connection.system_service().vms_service(avm.id).remove()

    def shutdownUserServices(self, userid, wait_until_done=False):
        # get user vms
        user_vms = self.connection.system_service().vms_service().list()
        # for each shutdown
        for avm in user_vms:
            self.connection.system_service().vms_service(avm.id).shutdown()
