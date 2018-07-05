import requests
import json


class OperWot:
    def __init__(self):
        self.apiKey = 'AIzaSyBZFkK1_OPvK3zbiwI6z5okk6-yu68b4P0'
        self.clientId = '381603779315-hcucm7hb0qjhuq1rkckgqvbubijodoaq.apps.googleusercontent.com '

    def rqUrlReport(self):
        url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {'client': {'clientId': self.clientId, 'clientVersion': "0.1"},
                   'threatInfo': {'threatTypes': ["SOCIAL_ENGINEERING", "MALWARE",
                                                  "THREAT_TYPE_UNSPECIFIED", "POTENTIALLY_HARMFUL_APPLICATION",
                                                  "UNWANTED_SOFTWARE"],
                                  'platformTypes': ["ANY_PLATFORM"],
                                  'threatEntryTypes': ["URL"],
                                  'threatEntries': [{'url': "https://www.naver.com/"}]}}
        params = {'key': self.apiKey}
        r = requests.post(url, params=params, json=payload)
        # Print response
        print(r)
        print(r.json())


def test():
    obOperWot = OperWot()
    obOperWot.rqUrlReport()


if __name__ == '__main__':
    test()
