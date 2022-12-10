from bottle import route, run, template, request, response, hook, post

from OpenSSL import crypto, SSL
from os.path import join
import random
from os import uname
import subprocess as sp
import hashlib

CN=uname()[1]
path='/etc/ems/certs/'
pubkey = "client.csr"
privkey = "client.key" 
pubkey = join(path, pubkey)
privkey = join(path, privkey)


BUF_SIZE = 65536 

nginx_conf="/etc/ems/nginx_config/device_domain.conf"
mosquitto_conf="/etc/ems/mqtt_config/mosquitto.conf"


@hook('after_request')
def enable_cors():
    """
    You need to add some headers to each request.
    Don't use the wildcard '*' for Access-Control-Allow-Origin in production.
    """
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'PUT, GET, POST, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token'

def hash_file (anyfile):
    sha1 = hashlib.sha1()
    with open(anyfile, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha1.update(data)
    return sha1.hexdigest()

def mqtt_config_file(conf_file):
    print ("Configure MQTT file")
    topic_name=hash_file(privkey)
    mqtt_config_content="""
listener 1883
persistence false
log_dest stdout
allow_anonymous true
connection_messages true
connection m1m0
address cloud.mqtt.medium.com:8883
# certificate file paths
bridge_cafile /etc/ems/certs/ca.crt
bridge_certfile /etc/ems/certs/client.crt
bridge_keyfile /etc/ems/certs/client.key
bridge_insecure true
topic  {ordinal}  both 1\n""".format(length='multi-line', ordinal=topic_name)
    open(conf_file, "wt").write(str(mqtt_config_content))
    return 'Done'
    

def nginx_config_file(conf_file):
    nginx_config_content="""
server {
listen 443 ssl;
server_name device.mqtt.local;
proxy_ssl_server_name on;
ssl_certificate    /etc/ems/certs/client.crt;  ## Use your own trusted certificate from CA/SSLTrust
ssl_certificate_key /etc/ems/certs/client.key; ## Use your own trusted certificate from CA/SSLTrust
ssl_client_certificate /etc/ems/certs/ca.crt;  ## Use your own trusted certificate from CA/SSLTrust

ssl_verify_client on;

ssl_prefer_server_ciphers on;

keepalive_timeout 10;
ssl_session_timeout 5m;
    location / {
        root /usr/share/nginx/html/ ;
        }
}
    """
    open(conf_file, "wt").write(str(nginx_config_content))
    return 'Ok'
 
@route('/api/device/get-hash',method=['OPTIONS', 'GET'])
def get_hash ():
    sha1 = hashlib.sha1()
    with open(privkey, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha1.update(data)
    return sha1.hexdigest()

@route('/api/device/csr',method=['OPTIONS', 'GET'])
def generate_csr():
    # print ("dummy")
    # if get CSR request this function will send command to 
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    # creaing the CRS request
    req = crypto.X509Req()
    req.get_subject().C = 'DE'
    req.get_subject().ST = 'Berlin'
    req.get_subject().L = 'Berlin'
    req.get_subject().O = 'Co-Lico'
    req.get_subject().OU = 'Leelly'
    req.get_subject().CN = 'mydevice'
    req.get_subject().emailAddress = 'something@anything.com'
    req.set_pubkey(k)
    req.sign(k, 'sha256')
    key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    open(pubkey,"wt").write(csr.decode("utf-8"))
    open(privkey, "wt").write(key.decode("utf-8") )
    return csr.decode("utf-8")


@post('/api/device/upload/ca', method=['OPTIONS', 'POST'])
def save_ca_crt():
    data=request.body.read()
    open(join(path, 'ca.crt'), "wt").write(str(request.body.getvalue().decode("utf-8")))
    #csrInfo = sp.check_output(['openssl','x509' , '-req', '-in', 'somefile.txt', '-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-out','client.crt','-days','360'])
    return 'ca.crt uploaded to device.'
    
@post('/api/device/upload/cert', method=['OPTIONS', 'POST'])
def save_client_crt():
    data=request.body.read()
    open(join(path, 'client.crt'), "wt").write(str(request.body.getvalue().decode("utf-8")))
    nginx_config_file(nginx_conf)
    mqtt_config_file(mosquitto_conf)
    return 'client.crt uploaded to device.'


run(host='0.0.0.0', port=8081, debug=True)
