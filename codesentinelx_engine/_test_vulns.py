import os
import subprocess
import hashlib
import random
import requests
import pickle
import yaml
from lxml import etree

# SQL Injection
cursor.execute("SELECT * FROM users WHERE id = " + user_input)

# Command Injection
os.system("rm -rf " + path)
subprocess.run("ls " + name, shell=True)

# Path Traversal
open(request.args.get("file"), "r").read()
send_file(request.args["path"])

# Weak Cryptography
hashlib.md5(data)
hashlib.sha1(data)

# Insecure Deserialization
pickle.loads(data)
yaml.load(data)

# Unsafe eval
eval(user_code)
exec(user_code)

# SSRF
requests.get(request.args.get("url"))

# JWT Misconfiguration
jwt.decode(token, verify=False)

# NoSQL Injection
db.find(request.body)

# LDAP Injection
ldap_conn.search("(uid=" + username + ")", scope)

# XXE
parser = etree.XMLParser()
etree.fromstring(xml_data)

# Open Redirect
return redirect(request.query.get("next"))

# File Inclusion
include(request.GET.get("page"))

# Insecure Cookie
response.set_cookie("session", token, secure=False)

# Rate Limiting
rateLimit({ max: 0 })

# Sensitive Data Logged
logger.info("User password: " + password)

# Authentication Flaw
@csrf_exempt

# Prototype Pollution
_.merge({}, req.body)

# Session Weakness
session.session_id = sid

# XPath Injection
xpath_query = "//user[name='" + username + "']"

# Secrets
api_key = "sk-abcdefghijklmnopqrstuvwxyz1234"

# Race Condition
if os.access(path, os.R_OK):
    with open(path) as f:
        data = f.read()

# Security Misconfiguration
debug = True
