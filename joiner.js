const fs = require('fs');
const path = require('path');
const requests = require('axios');
const readline = require('readline');

const tkn = "MTA2MDQ4MDUzODM2MTczMzE3MQ.GijqWM.wc_5d921z8lYbGOkcSDDtBNp3tP490gcaYAvoc";

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function addtoGuild(id, access, guild){
    while (1){
        try{
            url = `https://discord.com/api/v9/guilds/${guild}/members/${id}`
            data = {
            "access_token" : access,
            }
            headers = {
            "Authorization" : `Bot ${tkn}`,
            'Content-Type': 'application/json'

            }
            // response = await requests.put(url=url, headers=headers, json=data)
            response = await requests.put(url, data, { headers: headers })
            if ( response.status == 204 || response.status == 201 || response.status == 200 ){
                console.log(`[INFO]: successfully added ${id} to ${guild}`)
                break;
            }
            else if ( response.status == 429 ) {
                sleep(response.json()['retry_after']);
                continue;
            }
            else if ( response.status == 403 ) {
                console.log(`[ERROR]: ${id} is banned from ${guild}`)
                break;
            }
            else{
                console.log(response.status)
                console.log(response.text)
                break;
            }
        } catch (error) { console.log(error) }
    }

}
async function main() {
  const fileStream = fs.createReadStream('database.txt');

  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });


  for await (const line of rl) {
    ok = line.split(":")
    id = ok[0]
    access = ok[1]
    guild = "1060488426719297586"
    // console.log(id, access, guild)
    await addtoGuild(id, access, guild)
    // break;
    // console.log(line);
  }
}

main();

