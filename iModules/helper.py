import yaml, json, requests

def loadYML(infile):
  with open(infile,'r') as stream:
    try:
      data = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
      print(exc)
  return data

# ANSI Colors
cBLK  = "\033[1;30m"
cRED  = "\033[38;5;197m"
cGRN  = "\033[1;32m"
cYEL  = "\033[1;33m"
cBLUE = "\033[1;34m"
cMGNT = "\033[1;35m"
cCYAN = "\033[1;36m"
cWHT  = "\033[1;37m"
cPNK  = "\033[38;5;219m"
cPURP = "\033[38;5;141m"
e     = "\033[0m"

# Global 
CONFIG   = loadYML('config.yml')

def makeAPIRequest(url, method = 'GET', headers = {}, data = {}):
    if not 'Accept' in headers:
        headers['Accept'] = 'application/json'

    proxies = {}
    if CONFIG['options']['use_proxy']:
        proxies = CONFIG['proxies']

    if method == 'GET':
        response = requests.get(url, headers=headers, proxies=proxies)
    elif method == 'POST':
        response = requests.post(url, data=data, headers=headers, proxies=proxies)

    if response.status_code == requests.codes.not_found:
        return {}
    if response.status_code != requests.codes.ok:
        response.raise_for_status()
    try:
        response_data = json.loads(response.content)
    except json.decoder.JSONDecodeError as e:
        print(f'Error getting API info: {e}')
        return None
    return response_data
