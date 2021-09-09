import requests, json
from iModules.helper import *

FILE_REPORT_URL = 'https://www.virustotal.com/api/v3/files/{}'
REMOVE_ITEMS = [
    'size', 'magic',
    'last_analysis_results',
    'sha1', 'sha256', 'md5',
    'type_extension', 'type_tag',
    'type_description'
]

class VirusTotal:
    def __init__(self, apikey):
        if not apikey or apikey == '':
            raise ValueError('VirusTotal API Key must be defined!')
        self.apikey = apikey

    def _make_request(self, url, headers = {}):
        if not 'Accept' in headers:
            headers['Accept'] = 'application/json'
        
        proxies = {}
        if CONFIG['options']['use_proxy']:
            proxies = CONFIG['proxies']
        response = requests.get(url, headers=headers, proxies=proxies)

        if response.status_code == requests.codes.not_found:
            return {}
        if response.status_code != requests.codes.ok:
            response.raise_for_status()
        try:
            response_data = json.loads(response.content)
        except json.decoder.JSONDecodeError as e:
            print(f'Error getting VirusTotal info: {e}')
            return None
        return response_data

    def getFileInfo(self, fhash):
        headers = { 'x-apikey': self.apikey }
        fileinfo = self._make_request(FILE_REPORT_URL.format(fhash), headers)
        
        if fileinfo != None and len(fileinfo) > 0:
            for item in REMOVE_ITEMS:
                if item in fileinfo['data']['attributes']:
                    del fileinfo['data']['attributes'][item]
        return fileinfo

