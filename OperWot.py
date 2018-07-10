import requests


class OperWot:
    def __init__(self):
        self.apiKey = 'AIzaSyBZFkK1_OPvK3zbiwI6z5okk6-yu68b4P0'

    # 해당 Url이 멀웨어일 경우 True 아니면 False
    def isMalwareUrl(self, dns):
        url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {'threatInfo': {'threatTypes': ["MALWARE"],
                                  'platformTypes': ["WINDOWS"],
                                  'threatEntryTypes': ["URL"],
                                  'threatEntries': [{'url': dns}
                                                    ]}}
        params = {'key': self.apiKey}
        r = requests.post(url, params=params, json=payload)
        # return response
        return len(r.json())
