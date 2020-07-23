from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
import json
from datetime import datetime
import logging
from lib.ldap import cLDAP
from base64 import urlsafe_b64decode
from service.ldap_service import LdapUser, LdapGroup
from service.ovirt_service import OvirtEngineService
from config import ProductionConfig
from base64 import urlsafe_b64encode
from flask_httpauth import HTTPBasicAuth

basic_auth = HTTPBasicAuth()

application = Flask(__name__)
application.config.from_object(ProductionConfig())

# enable LDAP service
cLDAP(application)

# enable database plugin
db = SQLAlchemy(application)

from domain.models import ApiUser, User

@basic_auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = ApiUser.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = ApiUser.query.filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

#@token_auth.verify_token
#def verify_token(token):
#    # first try to authenticate by token
#    user = ApiUser.verify_auth_token(token)
#    if not user:
#        return False
#    g.user = user
#    return True


@application.route('/')
def hello_world():
    return {'status': "error",'message':'Not a vaild request'}, 404

@application.route('/api/token')
@basic_auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({ 'token': token.decode('ascii') })

@application.route('/group/add/user', methods=['POST'])
@basic_auth.login_required
def add_user_to_ldap_group():
    user_data = request.get_json()
    user_group = LdapGroup.set_basedn(
        application.config['LDAP_AUTH_GROUP_BASEDN']
    ).query.filter(f"(cn={user_data['group_name']})").first()
    user_group.members = user_data["userid"]
    add_group_msg = user_group.save()
    if (add_group_msg):
        res = jsonify({'status': "success", 'message': "User added to group"})
        res.headers["content-type"] = "application/json"
        return res, 201
    else:
        res = jsonify({'status': "error", 'message': "Error. Failed to adding user "})
        res.headers["content-type"] = "application/json"
        return res, 503

@application.route('/group/delete/user/<uidBase64Hash>')
@basic_auth.login_required
def delete_user_from_ldap_group(uidBase64Hash):
    ldap_userid, ldap_group = urlsafe_b64decode(uidBase64Hash).decode('utf-8').split("|")
    user_group = LdapGroup.set_basedn(
        application.config['LDAP_AUTH_GROUP_BASEDN']
    ).query.filter(f"(cn={ldap_group})").first()

    if not user_group:
        raise RuntimeError(f"Group {ldap_group} doesn't exist")

    # delete user from group ldap
    add_group_msg = LdapGroup.remove_user(ldap_userid,ldap_group,application.config['LDAP_AUTH_GROUP_BASEDN'])

    if (add_group_msg):
        res = jsonify({'status': "success", 'message': f"User deleted from group"})
        res.headers["content-type"] = "application/json"
        return res, 201
    else:
        res = jsonify({'status': "error"
                    , 'message': f"Error. Failed to delete user {ldap_userid} from group {ldap_group}"
                    , "service_error": add_group_msg
        })
        res.headers["content-type"] = "application/json"
        return res, 503

@application.route('/user/add', methods=['POST'])
@basic_auth.login_required
def add_user_to_services():
    user_data = request.get_json()
    if user_data == None:
        raise RuntimeError("Invalid user data")
    user_auth_domain = user_data.pop("user_auth_domain")
    user_data["dn"] = f"uid={user_data['username']}-{user_data['userid']},{application.config['LDAP_AUTH_BASEDN']}"
    user_data["base_dn"] = application.config["LDAP_AUTH_BASEDN"]
    user_data["name"] = f"{user_data['username']} {user_data['surname']}"
    user_data["home"] = "/dev/null"
    if "gid" not in user_data:
        user_data["gid"] = 1004
    if "billing_id" not in user_data:
        user_data["billing_id"] = user_data["userid"]
    if "group_name" not in user_data:
        user_data["group_name"] = "Cloudxtiny"

    group_name = user_data.pop("group_name")

    # getOrCreate
    if User.query.filter_by(email=user_data['email']).scalar() is None:
        newClient = User(username=user_data['username']
                , email=user_data['email']
                , first_name=user_data["firstname"]
                , last_name=user_data["surname"]
                , billing_id=user_data["userid"]
                , billing_product_id=user_data["billing_product_id"]
                , ldap_group_name=group_name
                , ovirt_auth_domain=user_auth_domain
             )
        db.session.add(newClient)
    else:
        newClient =  User.query.filter_by(email=user_data['email']).first()
        newClient.username=user_data['username']
        newClient.first_name=user_data["firstname"]
        newClient.last_name=user_data["surname"]
        newClient.billing_id=user_data["userid"]
        newClient.billing_product_id=user_data["billing_product_id"]
        newClient.ldap_group_name=group_name
        newClient.ovirt_auth_domain=user_auth_domain
        newClient.updated = datetime.utcnow

    user_data.pop("billing_product_id")
    user = LdapUser(**user_data)
    if (user.save() == True):

         # add user to relevant group
        user_group = LdapGroup.set_basedn(
             application.config['LDAP_AUTH_GROUP_BASEDN']
        ).query.filter(f"(cn={group_name})").first()
        user_group.members = user_data['username']
        try:
            add_group_msg = user_group.save()
        except Exception as ex:
            if ' memberUid:' in str(ex) and 'already exists' in str(ex):
                add_group_msg = True
            else:
                add_group_msg = str(add_group_msg)
                # adding to group failed so delete user from ldap
                LdapUser.set_basedn(
                    application.config['LDAP_AUTH_BASEDN']
                ).query.filter(f"(uid={user.username})").first().delete()

        if (add_group_msg == True):

            try:
                # added user to database and send ecrypted password
                encrypted_data = User.encrypt_username_password(user_data['username'], user_data['password'])
                newClient.encrypted_ovirt_auth_hash = encrypted_data["ct_bytes"]
                newClient.encrypted_ovirt_auth_iv =  encrypted_data["iv"]

                # get ovirt userid by logging in
                OvirtEngineService.loginCreatedUser(newClient.username
                                                    , user_data['password']
                                                    , newClient.ovirt_auth_domain
                                                )
                found_user = None
                user_search = OvirtEngineService().getUserDetailsByName(user_data['firstname'])
                for auser in user_search:
                    if auser.user_name == f"{newClient.username}@{newClient.ovirt_auth_domain}":
                        found_user = auser

                if found_user:
                    newClient.ovirt_user_id = found_user.id
                else:
                    raise RuntimeError(f"Could not find user {user_data['firstname']}@{newClient.ovirt_auth_domain} in Ovirt Service")

                application.logger.debug(newClient.dump_object())
                db.session.commit()

                result = json.dumps({
                    'java_ciphertext': urlsafe_b64encode(
                        encrypted_data["iv"] + encrypted_data["ct_bytes"]
                    ).decode('utf-8')
                    , "auth_domain": user_auth_domain
                })
            except Exception as ex:
                # rollback adding the user to LDAP
                LdapUser.set_basedn(
                    application.config['LDAP_AUTH_BASEDN']
                ).query.filter(f"(uid={user_data['username']})").first().delete()

                LdapGroup.remove_user(
                    user_data['username']
                    , group_name
                    , application.config['LDAP_AUTH_GROUP_BASEDN']
                )

                OvirtEngineService().deleteUserAccount(found_user.id)

                # re-throw the exception.
                raise ex

            return result , 201
        else:
            res = jsonify({'status': "error", 'message': f"Error. Failed to adding user to group: {add_group_msg}"})
            res.headers["content-type"] = "application/json"
            return res , 503
    else:
        res = jsonify({'status': "error", 'message': "Error. Failed to adding user "})
        res.headers["content-type"] = "application/json"
        return res, 503

@application.route('/user/delete/<uidBase64Hash>')
@basic_auth.login_required
def delete_user_from_services(uidBase64Hash):
    ldap_userid, billing_id = urlsafe_b64decode(uidBase64Hash).decode('utf-8').split("|")
    # get User from database
    aclient = db.session.query(User).filter_by(billing_id=billing_id).first()

    if not aclient:
        raise RuntimeError(f"User '{ldap_userid}' not found in database")

    # delete from LDAP
    ldap_user = LdapUser.set_basedn(
        application.config['LDAP_AUTH_BASEDN']
    ).query.filter(f"(uid={ldap_userid})").first()

    if not ldap_user:
        raise RuntimeError("Error User doesn't exist")

    del_user_msg = ldap_user.delete()

    if (del_user_msg == True):
        # delete user from group ldap
        add_group_msg =  LdapGroup.remove_user(
            aclient.username
            , aclient.ldap_group_name
            , application.config['LDAP_AUTH_GROUP_BASEDN']
        )

        # delete from ovirt server
        OvirtEngineService().deleteUserAccount(aclient.ovirt_user_id)

        # set user as inactive
        aclient.active = False
        application.logger.debug(aclient.dump_object())
        db.session.commit()

        res = jsonify({"status":"success", "message":"User deleted"})
        res.headers["content-type"] = "application/json"
        return res
    else:
        return {'error': 503, 'message': f"Failed to delete user failed: {del_user_msg}"}, 503

@application.route('/group/add', methods=['POST'])
@basic_auth.login_required
def add_group_to_ldap():
    # Add to LDAP
    group_data = request.get_json()
    group_data["dn"] = f"cn={group_data['group_name']},{application.config['LDAP_AUTH_GROUP_BASEDN']}"
    group_data["base_dn"] = application.config["LDAP_AUTH_BASEDN"]
    group = LdapGroup(**group_data)
    if (group.save() == True):
        res = jsonify({'status': "success", 'message': f"Group {group_data['group_name']} added"})
        res.headers['content-type'] = 'application/json'
        return res, 201
    else:
        res = jsonify({'status': "error", 'message': "Error. Failed to adding user "})
        res.headers['content-type'] = 'application/json'
        return res, 503

@application.route('/group/delete/<uidBase64Hash>')
@basic_auth.login_required
def delete_group_from_ldap(uidBase64Hash):
    print(uidBase64Hash)
    ldap_groupname = urlsafe_b64decode(uidBase64Hash).decode('utf-8')
    print(ldap_groupname)
    # delete from LDAP
    del_group_msg = LdapGroup.set_basedn(
        application.config['LDAP_AUTH_GROUP_BASEDN']
    ).query.filter(f"(cn={ldap_groupname})").first().delete()

    # delete from Ovirt server

    if (del_group_msg == True):
        res = jsonify({"status":"success", "message":"Group deleted"})
        res.headers['content-type']  = 'application/json'
        res.headers["content-type"] = "application/json"
        return res
    else:
        return {'error': 503, 'message': f"Failed to delete user failed: {del_group_msg}"}, 503

@application.errorhandler(Exception)
def handle_exceptions(e):
    res = jsonify({"status":"Error","message":f"Request failed with exception: {str(e)}"})
    res.headers['content-type'] = "application/json"
    application.logger.exception(e)
    return res, 500

@basic_auth.error_handler
def unauthorised_user_basic_auth():
    return unauthorised_user()

def unauthorised_user():
    failed_response = jsonify({"status": "error", "message": "Your are not authorised to use these services."})
    failed_response.status_code = 401
    failed_response.headers['content-type'] = "application/json"
    return failed_response

def create_admin_api_user():
    admin = ApiUser(username="admin")
    admin.hash_password(application.config['API_ADMIN_PASSWORD'])
    db.session.add(admin)
    db.session.commit()

if __name__ == '__main__':
    gunicorn_logger = logging.getLogger("gunicorn.error")
    application.logger.handlers = gunicorn_logger.handlers
    application.logger.setLevel(gunicorn_logger.level)
    application.run()
