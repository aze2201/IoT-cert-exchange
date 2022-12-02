import json
from functools import wraps

from flask import Flask, g, jsonify, request, redirect, render_template
from flask_cors import CORS
from flask_oidc import OpenIDConnect

from OpenSSL import crypto, SSL
from os.path import join
import random
from os import uname, system
import subprocess as sp

import uuid
import os 

import sqlite3

from pathlib import Path
cert_path="/root/pki"
Path(cert_path).mkdir(parents=True, exist_ok=True)
ca_crt=join(cert_path,'ca.crt')
ca_key=join(cert_path,'ca.key')
clr_pem = join(cert_path,'root.crl.pem')

cert_db = '/root/app/cert.db'
print (cert_db)

app = Flask(__name__)
CORS(app)

SECRET_KEY = 'test_secret_key'

app.config.update({
    'SECRET_KEY': SECRET_KEY,
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'oidc-config.json',
    'OIDC_OPENID_REALM': 'i2g-iam',
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'OIDC_TOKEN_TYPE_HINT': 'access_token'
})


class NewOpenIDConnect(OpenIDConnect):
    def accept_token_modified(self, require_token=False, scopes_required=None, render_errors=True):
        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                """
                this method is pretty much the same as the accept_token provided in the parent class with a small change
                if there's a specific header (ie. X-FORWARDED-HOST), then we'll let flask-oidc authenticate
                if not, we can skip the authentication step and proceed
                """
                print('HEADERS ############################################')
                print(request.headers)

                if True:  # will add logic later, but this is where we check if we authenticate or not
                    print("Skip authenticating...")
                    return view_func(*args, **kwargs)

                print("request coming through proxy, authenticating...")
                token = None
                if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Bearer '):
                    token = request.headers['Authorization'].split(None,1)[1].strip()
                if 'access_token' in request.form:
                    token = request.form['access_token']
                elif 'access_token' in request.args:
                    token = request.args['access_token']

                validity = self.validate_token(token, scopes_required)
                if (validity is True) or (not require_token):
                    return view_func(*args, **kwargs)
                else:
                    response_body = {
                        'error': 'invalid_token',
                        'error_description': validity
                    }
                    if render_errors:
                        response_body = json.dumps(response_body)
                    return response_body, 401, {'WWW-Authenticate': 'Bearer'}
            return decorated
        return wrapper


oidc = NewOpenIDConnect(app)

@app.route('/', methods=['GET'])
@oidc.require_login
def no_token_api():
    #u=str(g.oidc_token_info['preferred_username'])
    u = oidc.user_getfield("preferred_username")
    conn=sqlite3.connect(cert_db,check_same_thread=False)
    cursor = conn.cursor()
    sql_command='insert or ignore into users (username) values (\''+u+'\');'
    cursor.execute(sql_command)
    conn.commit()
    return redirect('http://device.ems.local:81')


@app.route('/api/cloud/device-mqtt-topic', methods=['OPTIONS', 'POST'])
@oidc.accept_token(require_token=True)
def get_topic():
    # make a temporary directory
    u=str(g.oidc_token_info['preferred_username'])
    topic_name=str(request.form['device-topic'])
    conn=sqlite3.connect(cert_db, check_same_thread=False)
    cursor = conn.cursor()
    sql_command = 'update users set device_topic=\''+topic_name+'\' where username=\''+u+'\';'
    cursor.execute(sql_command)
    conn.commit()
    return 'topic name setup done'

@app.route('/api/cloud/sign-csr', methods=['OPTIONS', 'POST'])
@oidc.accept_token(require_token=True)
def sign_api():
    # make a temporary directory
    u=str(g.oidc_token_info['preferred_username'])
    tmp_dir=join('/tmp/',str(uuid.uuid4()))
    os.mkdir(tmp_dir)
    tmp_CSR_file=join(tmp_dir,'somefile.txt')
    tmp_CRT_file=join(tmp_dir,'client.crt')
    open(tmp_CSR_file, "wt").write(str(request.form['cert']))
    sign = sp.check_output(['openssl','x509' , '-req', '-in', tmp_CSR_file, '-CA',join(cert_path,'ca.crt'),'-CAkey',join(cert_path,'ca.key'),'-CAcreateserial','-out',tmp_CRT_file,'-days','3600'])
    text_file = open(tmp_CRT_file, "r")
    data = text_file.read()
    text_file.close()
    conn=sqlite3.connect(cert_db, check_same_thread=False)
    cursor = conn.cursor()
    sql_command = 'update users set cert=\''+data+'\' where username=\''+u+'\';'
    cursor.execute(sql_command)
    conn.commit()
    return data


@app.route('/api/cloud/ca',methods=['OPTIONS', 'POST'])
@oidc.accept_token(require_token=True)
def getca ():
    ca_file = open(ca_crt, "r")
    data = ca_file.read()
    ca_file.close()
    return data

@app.route('/revoke', methods=['OPTIONS', 'GET'])
@oidc.require_login
def revoke_page():
    if oidc.user_loggedin:
        page_token = json.loads(oidc.credentials_store[oidc.user_getfield('sub')])['access_token']
    u = oidc.user_getfield("preferred_username")
    conn=sqlite3.connect(cert_db, check_same_thread=False)
    cursor = conn.cursor()
    sql_command = 'select cert from users where username=\''+u+'\';'
    print_cert = cursor.execute(sql_command).fetchall()[0][0]
    return render_template('revoke.html', user=u, cert=print_cert, access_token = page_token)


@app.route('/api/cloud/revoke-crt', methods=['OPTIONS', 'POST'])
@oidc.accept_token(require_token=True)
def revoke_api():
    u=str(g.oidc_token_info['preferred_username'])
    tmp_dir=join('/tmp/',str(uuid.uuid4()))
    os.mkdir(tmp_dir)
    tmp_remoke_file=join(tmp_dir,'revoked.crt')
    conn=sqlite3.connect(cert_db, check_same_thread=False)
    cursor = conn.cursor()
    sql_command = 'select cert from users where username=\''+u+'\';'
    revoke_cert = cursor.execute(sql_command).fetchall()[0][0]
    # save cert which need to be revoked
    open(tmp_remoke_file, "wt").write(str(revoke_cert))
    revoke_cert = sp.check_output(['openssl','ca' , '-config', join(cert_path,'ca.conf'), '-revoke', tmp_remoke_file,'-cert', ca_crt,'-keyfile',ca_key])
    update_clr_crt = sp.check_output(['openssl','ca' , '-config', join(cert_path,'ca.conf'), '-gencrl','-cert', ca_crt,'-keyfile',ca_key,'-out',clr_pem])
    # update permission
    chown = sp.check_output(['chown','-R','mosquitto:www-data',cert_path])
    # reload mosquitto
    os.system('systemctl restart mosquitto.service')
    # remove temporary revoke cert with path
    return 'cert is revoked'


@app.route('/my-device', methods=['OPTIONS', 'GET', 'POST'])
@oidc.require_login
def my_device():
    # not very secure. only for PoC. 
    u = oidc.user_getfield("preferred_username")
    conn=sqlite3.connect(cert_db, check_same_thread=False)
    cursor = conn.cursor()
    sql_command = 'select device_topic from users where username=\''+u+'\';'
    device_topic= cursor.execute(sql_command).fetchall()[0][0]
    return render_template('my-device.html', topic= device_topic)


if __name__ == '__main__':
    app.run(port=8080)
