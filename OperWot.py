import requests
import pprint


class OperWot:
    def __init__(self):
        self.apiKey = 'AIzaSyBZFkK1_OPvK3zbiwI6z5okk6-yu68b4P0'

    def rqUrlReport(self, sUrl):
        url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {'threatInfo': {'threatTypes': ["MALWARE"],
                                  'platformTypes': ["WINDOWS"],
                                  'threatEntryTypes': ["URL"],
                                  'threatEntries': [{'url': sUrl}
                                                    ]}}
        params = {'key': self.apiKey}
        r = requests.post(url, params=params, json=payload)
        # return response
        return r.json()


def test():
    obOperWot = OperWot()
    pprint.pprint(obOperWot.rqUrlReport("http://malware.testing.google.test/testing/malware/"))


if __name__ == '__main__':
    test()
