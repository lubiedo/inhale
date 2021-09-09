import json, os
from iModules.helper import *

VT_API_URL = 'https://www.virustotal.com/api/v3'
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
        self.headers = { 'x-apikey': self.apikey }

    def sampleDownload(self, fhash, path):
        url = makeAPIRequest(f'{VT_API_URL}/files/{fhash}/download_url', headers = self.headers)
        if not url or 'data' not in url or len(url) == 0:
            return ''

        fd = None
        fullpath = f'{path}{fhash}'
        try:
            os.makedirs(path, exist_ok=True)
            fd  = open(fullpath, 'wb')
            res = makeSimpleRequest(url['data'], self.headers)
            for chunk in res.iter_content(chunk_size = 512):
                fd.write(chunk)
            fd.close()
        except Exception as e:
            print(e)
            return ''
        return fullpath

    def getFileInfo(self, fhash):
        fileinfo = makeAPIRequest(f'{VT_API_URL}/files/{fhash}', headers = self.headers)
        
        if fileinfo != None and len(fileinfo) > 0:
            for item in REMOVE_ITEMS:
                if item in fileinfo['data']['attributes']:
                    del fileinfo['data']['attributes'][item]
        return fileinfo

