from iModules.helper import *

BAAZAR_API_URL = 'https://mb-api.abuse.ch/api/v1/'
INTEL_DATA = [ 'intelligence', 'vendor_intel', 'delivery_method' ]

class MalwareBaazar:
    def __init__(self, fhash):
        self.hash = fhash

    def getInfo(self):
        params = { 'query': 'get_info', 'hash': self.hash }
        fileinfo = makeAPIRequest(BAAZAR_API_URL, method = 'POST', data = params)
        if not fileinfo or fileinfo['query_status'] == 'hash_not_found':
            return None
        return fileinfo

    def getIntel(self):
        info = self.getInfo()
        if not info:
            return None

        return_info = {}
        for k in INTEL_DATA:
            return_info[k] = info['data'][0][k]
        return return_info
