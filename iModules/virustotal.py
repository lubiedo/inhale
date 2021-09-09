import json
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

    def getFileInfo(self, fhash):
        headers = { 'x-apikey': self.apikey }
        fileinfo = makeAPIRequest(FILE_REPORT_URL.format(fhash), headers = headers)
        
        if fileinfo != None and len(fileinfo) > 0:
            for item in REMOVE_ITEMS:
                if item in fileinfo['data']['attributes']:
                    del fileinfo['data']['attributes'][item]
        return fileinfo

