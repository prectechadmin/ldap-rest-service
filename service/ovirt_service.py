from flask import current_app
import logging
import ovirtsdk4 as sdk
import ovirtsdk4.types as types

class OvirtEngineService:

    @staticmethod
    def loginCreatedUser(username,password,domain):
        connection = sdk.Connection(
            url=current_app.config["OVIRT_ENGINE_URL"],
            username=f"{username}@{domain}",
            password=password,
            insecure=True, # No host name TLS verification. Doesn't work in Openshift
            ca_file=current_app.config["OVIRT_CERT_PATH"],
            debug=current_app.config["DEBUG"],
            log=logging.getLogger("OvirtService"),
        )
        vms_service = connection.system_service().vms_service()

        # Use the "list" method of the "vms" service to list all the virtual machines of the system:
        vms = vms_service.list()

        connection.close()

    def __init__(self, username=None, password=None,name=None,domain="internal"):
        self.is_admin = False
        self.domain = domain
        self.user = None
        if (name):
            self.name = name
            self.username = username
            self.password = password
        else:
            self.username = current_app.config["OVIRT_ADMIN_USER"]
            self.password = current_app.config["OVIRT_ADMIN_PASSWORD"]
            self.name = "admin"
            self.is_admin = True
            self.domain ="internal"

        self.connection = sdk.Connection(
            url=current_app.config["OVIRT_ENGINE_URL"],
            username=f"{self.username}@{self.domain}",
            password=self.password,
            insecure=True,  # No host name TLS verification. Doesn't work in Openshift
            ca_file=current_app.config["OVIRT_CERT_PATH"],
            debug=current_app.config["DEBUG"],
            log=logging.getLogger("OvirtService"),
        )

        if self.is_admin:
            self.user = self.connection.system_service().users_service().list(
                search=f'name={self.username}'
            )[0]
        else:
            ausers = self.connection.system_service().users_service().list(
                search=f'name={self.name}'
            )
            for auser in ausers:
                if auser.user_name == f"{self.username}@{self.domain}":
                    self.user = auser
            if not self.user:
                raise RuntimeError("Error could not find service User.")



    def __del__(self):
        self.connection.close()

    def getUserDetailsById(self, userid):
        # login as a user and get their user id
        if self.is_admin:
            return self.connection.system_service().users_service(userid)
        else:
            raise RuntimeError("Sorry only an admin user is allowed to perform this operation")

    def getUserDetailsByName(self, name):

        if self.is_admin:
            return self.connection.system_service().users_service().list(
                search=f'name={name}'
            )

        else:
            raise RuntimeError("Sorry only an admin user is allowed to perform this operation")

    def deleteUserAccount(self, userid):
        if self.is_admin:
            return self.connection.system_service().users_service().user_service(userid).remove()
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
