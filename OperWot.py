import requests
import json


class OperWot:
    def __init__(self):
        self.apiKey = 'AIzaSyBZFkK1_OPvK3zbiwI6z5okk6-yu68b4P0'
        self.clientId = '381603779315-hcucm7hb0qjhuq1rkckgqvbubijodoaq.apps.googleusercontent.com '

    def rqUrlReport(self):
        url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {'client': {'clientId': 'yourcompanyname', 'clientVersion': "1.5.2"},
                   'threatInfo': {'threatTypes': ["SOCIAL_ENGINEERING", "MALWARE"],
                                  'platformTypes': ["WINDOWS"],
                                  'threatEntryTypes': ["URL"],
                                  'threatEntries': [{'url': "https://search.naver.com/search.naver?where=nexearch&sm=top_hty&fbm=1&ie=utf8&query=safsaf"},
                                                    {"url": "http://www.urltocheck1.org/"},
                                                    {"url": "http://www.urltocheck2.org/"},
                                                    {"url": "http://www.urltocheck3.com/"}
                                                    ]}}
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
