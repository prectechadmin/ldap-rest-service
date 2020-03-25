from flask import Flask, request, abort, Response,jsonify
import os,sys,traceback
import requests
from flask_python_ldap import LDAP
from base64 import urlsafe_b64decode
from service.ldap_service import LdapUser, LdapGroup
from config import ProductionConfig, DevelopmentConfig
application = Flask(__name__)
application.config.from_object(DevelopmentConfig())

# enable LDAP plug
LDAP(application)

def is_authorised_user():
    if 'authorization' in request.headers:
        return request.headers['authorization'] == application.config['AUTH_TOKEN']
    else:
        failed_response = jsonify({"status":"error","message":"Your are not authorised to use this services."})
        failed_response.status_code = 401
        failed_response.headers['content-type'] = "application/json"
        abort(failed_response)

@application.route('/')
def hello_world():
    return {'status': "error",'message':'Not a vaild request'}, 404

@application.route('/group/add/user', methods=['POST'])
def add_user_to_ldap_group():
    is_authorised_user()
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
def add_ovirt_user_to_ldap():
    is_authorised_user()
    user_data = request.get_json()
    user_data["dn"] = f"uid={user_data['username']}-{user_data['userid']},{application.config['LDAP_AUTH_BASEDN']}"
    user_data["base_dn"] = application.config["LDAP_AUTH_BASEDN"]
    group_name = user_data.pop("group_name")
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

        if (add_group_msg):
            return user.encrypt_username_password() , 201
        else:
            res = jsonify({'status': "error", 'message': "Error. Failed to adding user "})
            res.headers["content-type"] = "application/json"
            return res , 503
    else:
        res = jsonify({'status': "error", 'message': "Error. Failed to adding user "})
        res.headers["content-type"] = "application/json"
        return res, 503

@application.route('/user/delete/<uidBase64Hash>')
def delete_ovirt_user_from_ldap(uidBase64Hash):
    is_authorised_user()
    ldap_userid = urlsafe_b64decode(uidBase64Hash).decode('utf-8')
    # delete from LDAP
    del_user_msg = LdapUser.set_basedn(
        application.config['LDAP_AUTH_BASEDN']
    ).query.filter(f"(uid={ldap_userid})").first().delete()

    # delete from Ovirt server

    if (del_user_msg == True):
        res = jsonify({"status":"success", "message":"User deleted"})
        res.headers["content-type"] = "application/json"
        return res
    else:
        return {'error': 503, 'message': f"Failed to delete user failed: {del_user_msg}"}, 503

@application.route('/group/add', methods=['POST'])
def add_group_to_ldap():
    is_authorised_user()
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
def delete_group_from_ldap(uidBase64Hash):
    is_authorised_user()
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

if __name__ == '__main__':
    application.run()
