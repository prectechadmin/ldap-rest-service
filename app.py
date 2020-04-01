from flask import Flask, request, abort, Response,jsonify, g
from flask_sqlalchemy import SQLAlchemy
import sys,traceback,json
from flask_python_ldap import LDAP
from base64 import urlsafe_b64decode
from service.ldap_service import LdapUser, LdapGroup
from service.ovirt_service import OvirtEngineService
from config import ProductionConfig, DevelopmentConfig
from base64 import urlsafe_b64encode
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth('Bearer')
multi_auth = MultiAuth(basic_auth, token_auth)

application = Flask(__name__)
application.config.from_object(ProductionConfig())

# enable LDAP service
LDAP(application)
# enable database plugin
db = SQLAlchemy(application)

from domain.models import ApiUser, User

@basic_auth.verify_password
def verify_password(username, password):
    user = ApiUser.query.filter_by(username = username).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True

@token_auth.verify_password
def verify_password(token):
    # first try to authenticate by token
    user = ApiUser.verify_auth_token(token)
    if not user:
        return False
    g.user = user
    return True


@application.route('/')
def hello_world():
    return {'status': "error",'message':'Not a vaild request'}, 404

@application.route('/api/token')
@basic_auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({ 'token': token.decode('ascii') })

@application.route('/group/add/user', methods=['POST'])
@multi_auth.login_required
def add_user_to_ldap_group():
    user_data = request.get_json()
    user_group = LdapGroup.set_basedn(
        application.config['LDAP_AUTH_GROUP_BASEDN']
    ).query.filter(f"(cn={user_data['group_name']})").first()
    user_group.members = user_data["userid"]
    print(user_group)
    add_group_msg = user_group.save()
    if (add_group_msg):
        res = jsonify({'status': "success", 'message': "User added to group"})
        res.headers["content-type"] = "application/json"
        return res, 201
    else:
        res = jsonify({'status': "error", 'message': "Error. Failed to adding user "})
        res.headers["content-type"] = "application/json"
        return res, 503

@application.route('/user/add', methods=['POST'])
@multi_auth.login_required
def add_ovirt_user_to_ldap():
    user_data = request.get_json()
    user_auth_domain = user_data.pop("user_auth_domain")
    user_data["dn"] = f"uid={user_data['username']}-{user_data['userid']},{application.config['LDAP_AUTH_BASEDN']}"
    user_data["base_dn"] = application.config["LDAP_AUTH_BASEDN"]
    group_name = user_data.pop("group_name")
    newClient = User(username=user_data['username']
            , email=user_data['email']
            , billing_id=user_data["billing_id"]
            , billing_product_id=user_data["billing_product_id"]
            , ldap_group_name=group_name
            , ovirt_auth_domain=user_auth_domain
         )
    user_data.pop("billing_id")
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

            # added user to database and send ecrypted password
            encrypted_data = User.encrypt_username_password(user_data['username'], user_data['password'],user_auth_domain)
            newClient.encrypted_ovirt_auth_hash = encrypted_data["ct_bytes"]
            newClient.encrypted_ovirt_auth_iv =  encrypted_data["iv"]

            # get ovirt userid
            newClient.ovirt_user_id = OvirtEngineService().getUserDetailsByUsername(
                user_data['username'],user_auth_domain
            ).id

            db.session.add(newClient)
            result = json.dumps({
                'java_ciphertext': urlsafe_b64encode(
                    encrypted_data["iv"] + encrypted_data["ct_bytes"] + "|" + user_auth_domain
                ).decode('utf-8')
            })

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
@multi_auth.login_required
def delete_ovirt_user_from_ldap(uidBase64Hash):
    ldap_userid, billing_id = urlsafe_b64decode(uidBase64Hash).decode('utf-8').split("|")
    # get User from database
    aclient = User.filter(User.billing_id == billing_id).first()

    # delete from LDAP
    del_user_msg = LdapUser.set_basedn(
        application.config['LDAP_AUTH_BASEDN']
    ).query.filter(f"(uid={ldap_userid})").first().delete()

    if (del_user_msg == True):
        # remove user from the group.
        user_group = LdapGroup.set_basedn(
            application.config['LDAP_AUTH_GROUP_BASEDN']
        ).query.filter(f"(cn={aclient.ldap_group_name})").first()
        new_group_members = [amember for amember in user_group.members if amember != aclient.username]
        user_group.members = new_group_members
        user_group.save()

        # delete from ovirt server
        OvirtEngineService().deleteUserAccount(aclient.ovirt_user_id)

        res = jsonify({"status":"success", "message":"User deleted"})
        res.headers["content-type"] = "application/json"
        return res
    else:
        return {'error': 503, 'message': f"Failed to delete user failed: {del_user_msg}"}, 503

@application.route('/group/add', methods=['POST'])
@multi_auth.login_required
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
@multi_auth.login_required
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
    print('-' * 60)
    traceback.print_exc(file=sys.stdout)
    print('-' * 60)
    return res, 500

@multi_auth.error_handler
def unauthorised_user():
    failed_response = jsonify({"status":"error","message":"Your are not authorised to use this services."})
    failed_response.status_code = 401
    failed_response.headers['content-type'] = "application/json"
    return failed_response


if __name__ == '__main__':
    application.run()
