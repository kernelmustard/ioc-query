#!/usr/bin/env python
import os
import requests
import json

# call corresponding function to query website apis for IOC
def query_md5(ioc,apiKeyDict,tagsList):
  url = 'https://www.virustotal.com/api/v3/files/'+ioc      # build url to query
  headers = { "X-Apikey": apiKeyDict["virustotal"] }        # specify api key authentication in header
  md5_virustotal_response = requests.get(url, headers=headers)  # send GET to VirusTotal API and read reponse into object
  if md5_virustotal_response.status_code == 200:  # if it is a successful query
    tagsList.append('virustotal')         # add a tag indicating a hit on VirusTotal

  url = 'https://hashlookup.circl.lu/lookup/md5/'+ioc
  md5_hashlookup_response = requests.get(url)
  if md5_hashlookup_response.status_code == 200:
    tagsList.append('hashlookup')

  url = 'https://mb-api.abuse.ch/api/v1/'
  data = {"query": "get_info", "hash": ioc}
  md5_malwarebazaar_response  = requests.post(url, data=data)
  if md5_malwarebazaar_response.status_code == 200:
    tagsList.append('malwarebazaar')

  return tagsList

def query_sha1(ioc,apiKeyDict,tagsList):
  url = 'https://www.virustotal.com/api/v3/files/'+ioc
  headers = { "X-Apikey": apiKeyDict["virustotal"] }
  sha1_virustotal_response = requests.get(url, headers=headers)
  if sha1_virustotal_response.status_code == 200: 
    tagsList.append('virustotal')

  url = 'https://hashlookup.circl.lu/lookup/sha1/'+ioc  
  sha1_hashlookup_response = requests.get(url)      
  if sha1_hashlookup_response.status_code == 200: 
    tagsList.append('hashlookup')

  url = 'https://mb-api.abuse.ch/api/v1/'+ioc
  data = {"query": "get_info", "hash": ioc}
  sha1_malwarebazaar_response = requests.post(url, data=data)
  if sha1_malwarebazaar_response.status_code == 200:
    tagsList.append('malwarebazaar')

  return tagsList

def query_sha256(ioc,apiKeyDict,tagsList):
  url = 'https://www.virustotal.com/api/v3/files/'+ioc
  headers = { "X-Apikey": apiKeyDict["virustotal"] }
  sha256_virustotal_response = requests.get(url, headers=headers)  
  if sha256_virustotal_response.status_code == 200:
    tagsList.append('virustotal')

  url = 'https://hashlookup.circl.lu/lookup/sha256/'+ioc  
  sha256_hashlookup_response = requests.get(url)      
  if sha256_hashlookup_response.status_code == 200: 
    tagsList.append('hashlookup')

  url = 'https://mb-api.abuse.ch/api/v1/'
  data = {"query": "get_info", "hash": ioc}
  sha256_malwarebazaar_response = requests.post(url, data=data)
  if sha256_malwarebazaar_response.status_code == 200:
    tagsList.append('malwarebazaar')

  url = 'https://api.maltiverse.com/sample/'+ioc
  sha256_maltiverse_response = requests.get(url)
  if sha256_maltiverse_response.status_code == 200: 
    tagsList.append('maltiverse')

  return tagsList # return tags so main() knows the URLs to link in the report
  
def query_ip(ioc,apiKeyDict,tagsList):
  url = 'https://www.virustotal.com/api/v3/ip_addresses/'+ioc
  headers = { "X-Apikey": apiKeyDict["virustotal"] }
  ip_virustotal_response = requests.get(url, headers=headers)   
  if ip_virustotal_response.status_code == 200:
    tagsList.append('virustotal')         

  if len(ioc) <= 15:  #Maltiverse only does ipv4, max len of ipv4 is 15
    url = 'https://api.maltiverse.com/ip/'+ioc
    ip_maltiverse_response = requests.get(url)
    if ip_maltiverse_response.status_code == 200:
      tagsList.append('maltiverse')

  url = 'https://ipinfo.io/' + ioc + '?token=' + apiKeyDict["ipinfo"]
  ip_ipinfo_response = requests.get(url)
  if ip_ipinfo_response.status_code == 200:
    tagsList.append('ipinfo')

  return tagsList

def query_domain(ioc,apiKeyDict,tagsList):
  url = 'https://www.virustotal.com/api/v3/domains/'+ioc
  headers = { "X-Apikey": apiKeyDict["virustotal"] }
  domain_virustotal_response = requests.get(url, headers=headers) 
  if domain_virustotal_response.status_code == 200:
    tagsList.append('virustotal')
    
  url = 'https://api.maltiverse.com/hostname/'+ioc
  domain_maltiverse_response = requests.get(url)
  if domain_maltiverse_response.status_code == 200:
      tagsList.append('maltiverse')

  return tagsList

def makeKeyFile(apiKeyDict):
  for key in apiKeyDict:  #get data into apiKeyDict
    apiKeyDict[key] = input("Paste your " + key + " API key: ")
  with open("keys.json", "w") as write_keys:
    json.dump(apiKeyDict, write_keys) # write apiKeyDict to keys.json

  return apiKeyDict   # return api keys for query headers

def main():

  print('Constructing IOC dictionary...')
  # dict with lists for each ioc type
  iocDict = {
    "md5": [],
    "sha1": [],
    "sha256": [],
    "ip": [],
    "domain": []
  }

  print('Reading API Keys...')
  try:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))  # cd to the path this file is being ran from
    with open("keys.json", "r") as keyFile:               # read keys.json into memory as keyFile
      apiKeyDict = json.load(keyFile)                       # deserialize file so it can be parsed into apiKeyDict
  except FileNotFoundError:
    print('keys.json does not exist. Creating...')
    apiKeyDict = { "virustotal": "", "recordedfuture": "", "ipinfo": "" }
    makeKeyFile(apiKeyDict)
    print(apiKeyDict)

  print('Reading input...')
  print('\nEnter your IOCs in the format tag:ioc\nAccepted tags: md5, sha1, sha256, imphash, ssdeep, ip, domain\nEnter "end^read" when finished.\n')
  inputList = []
  while exit != True:
    try:
      tag, ioc = input().split('^')                     # read tag^ioc from shell
      if tag == 'end' and ioc == 'read':                # if input is end:read, then finish reading input
        raise UnboundLocalError('Done reading input.')  
      iocDict[tag].append(ioc)                          # add the ioc to the proper key List in the iocDict
    except UnboundLocalError:                         # proper exit
      break
    except KeyError:      # KeyError raised when the tag specified doesn't exit within the iocDict
      print('\n','-'*20+'> Accepted tags: md5, sha1, sha256, ip, domain\n')
      continue
    except ValueError:      # ValueError raised when there arent a tag and ioc delimited by ^
      print('\n','-'*20+'> Parseable format =  <tag>^<ioc>\n')
      continue

  print('Constructing link lists...')
  virustotalList = []     # VirusTotal hits
  hashlookupList = []     # hashlookup hits
  malwarebazaarList = []  # MalwareBazaar hits
  maltiverseList = []     # Maltiverse hits

  print('Searching for MD5 hashes...')
  tagsList = [] # initialize tags list
  for ioc in iocDict['md5']:
    query_md5(ioc,apiKeyDict,tagsList)
    if 'virustotal' in tagsList:
      virustotalList.append('https://www.virustotal.com/gui/file/'+ioc)
    if 'hashlookup' in tagsList:
      hashlookupList.append('https://hashlookup.circl.lu/lookup/md5/'+ioc)
    if 'malwarebazaar' in tagsList:
      malwarebazaarList.append('https://bazaar.abuse.ch/browse.php?search=md5%3A'+ioc)
    else:
      continue

  print('Searching for SHA-1 hashes...')
  tagsList = [] # clear previously-assigned values
  for ioc in iocDict['sha1']:
    query_sha1(ioc,apiKeyDict,tagsList)
    if 'virustotal' in tagsList:
      virustotalList.append('https://www.virustotal.com/gui/file/'+ioc)
    if 'hashlookup' in tagsList:
      hashlookupList.append('https://hashlookup.circl.lu/lookup/sha1/'+ioc)
    else:
      continue

  print('Searching for SHA-256 hashes...')
  tagsList = []
  for ioc in iocDict['sha256']:
    query_sha256(ioc,apiKeyDict,tagsList)
    if 'virustotal' in tagsList:
      virustotalList.append('https://www.virustotal.com/gui/file/'+ioc)
    if 'hashlookup' in tagsList:
      hashlookupList.append('https://hashlookup.circl.lu/lookup/sha256/'+ioc)
    if 'malwarebazaar' in tagsList:
      malwarebazaarList.append('https://bazaar.abuse.ch/browse.php?search=sha256%3A'+ioc)
    if 'maltiverse' in tagsList:
      maltiverseList.append('https://maltiverse.com/search;query='+ioc)
    else:
      continue

  print('Searching for IPs...')
  tagsList = []
  for ioc in iocDict['ip']:
    query_ip(ioc,apiKeyDict,tagsList)
    if 'virustotal' in tagsList:
      virustotalList.append('https://www.virustotal.com/gui/ip-address/'+ioc)
    if 'maltiverse' in tagsList:
      maltiverseList.append('https://maltiverse.com/search;query='+ioc)
    else:
      continue

  print('Searching for domains...')
  tagsList = []
  for ioc in iocDict['domain']:
    query_domain(ioc,apiKeyDict,tagsList)
    if 'virustotal' in tagsList:
      virustotalList.append('https://www.virustotal.com/gui/domain/'+ioc)
    elif 'maltiverse' in tagsList:
        maltiverseList.append('https://maltiverse.com/hostname/'+ioc)
    else:
      continue

  print('Printing report...')
  print('-' * 40,str(len(virustotalList))+' VirusTotal hits','-' * 40)
  for link in virustotalList:
    print(link)
  print('-' * 40,str(len(hashlookupList))+' hashlookup hits','-' * 40)
  for link in hashlookupList:
    print(link)
  print('-' * 40,str(len(malwarebazaarList))+' MalwareBazaar hits','-' * 40)
  for link in malwarebazaarList:
    print(link)
  print('-' * 40,str(len(maltiverseList))+' Maltiverse hits','-' * 40)
  for link in maltiverseList:
    print(link)

if __name__ == '__main__':  # make sure this is the script being called
  main()