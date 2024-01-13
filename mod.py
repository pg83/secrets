import os
import sys
import json
import base64
import getpass
import subprocess

AES = '-aes-128-cbc'

def runbin(cmd, input):
    return subprocess.check_output(cmd, input=input)

def runtext(cmd):
    return runbin(cmd, None).decode()

def genkey(pp, salt):
    out = runtext([
        'openssl',
        'enc',
        '-pbkdf2',
        AES,
        '-k', pp,
        '-P',
    ] + salt)

    res = {}

    for l in out.splitlines():
        l = l.strip()

        if not l:
            continue

        a, b = l.split('=')

        res[a.strip()] = b.strip()

    return res

def gen(pp):
    return genkey(pp, [])

def key(pp, salt):
    return genkey(pp, ['-S', salt])

def encdec(key, iv, data, extra):
    return runbin(['openssl', 'enc', AES, '-K', key, '-iv', iv] + extra, data)

def encode(key, iv, data):
    return encdec(key, iv, data, [])

def decode(key, iv, data):
    return encdec(key, iv, data, ['-d'])

def read(pp, path):
    try:
        with open(path) as f:
            d = json.loads(f.read())
    except Exception as f:
        return ''.encode()

    k = key(pp, d['salt'])

    return decode(k['key'], k['iv'], base64.b64decode(d['data']))

def write(pp, path, data):
    k = gen(pp)

    d = {
        'salt': k['salt'],
        'data': base64.b64encode(encode(k['key'], k['iv'], data)).decode(),
    }

    with open(path, 'w') as f:
        f.write(json.dumps(d, indent=4, sort_keys=True))

pswd = getpass.getpass()
path = sys.argv[1]
data = read(pswd, path)

# TODO - do not materialize sensitive data
with open('tmp', 'wb') as f:
    f.write(data)

try:
    os.system(os.environ['EDITOR'] + ' tmp')
    write(pswd, path, open('tmp', 'rb').read())
finally:
    os.unlink('tmp')
