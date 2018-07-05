import requests
import ProcessInfo


class OperVt:
    def __init__(self):
        self.apiKeyTable = ["15b841c3fa1ea901a71c36690fb1a8f8602c197035089fd3721eb70542e6ff18",
                            "a20a96237a27217861127ded33458a6536e660ca66ef74f902cb8893bc03b995",
                            "93a9a6dd34946ee1f39e7fd56f31bd6c8623d5be6c5904d9148cb1d2dff4f3a4",
                            "b4b93ac9cb1475cff079481a07a996790811de555769c12cac28f72586063b30",
                            "2344e021f8741b0fd600eb1347771e0083789c63d931f108fd1d462787900910",
                            "0519a7c0998ff5f472932c0267f7d5ebd193384a4c3c0c96f1d16511a8d56c9d",
                            "dca12989d549ed952b292698d85fe89703b5e7ad6267e317375668524285a5ae"]
        self.apiKey = ""
        self.dicRpResult = {}
        self.intRpPositives = 0
        self.intRpTotal = 0

    # API Report 결과를 딕셔너리로 리턴
    def rqReport(self, md5Hash):
        params = {'apikey': self.apiKey, 'resource': md5Hash}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                params=params, headers=headers)
        json_response = response.json()
        return json_response

    # API Key 설정
    def setApiKey(self, apiKey):
        self.apiKey = apiKey

    # 리포트 결과를 분석한 정보를 저장
    def rpAnalysis(self, md5Hash):
        dicRp = self.rqReport(md5Hash)
        self.intRpPositives = dicRp['positives']
        scanList = [i for i in dicRp['scans'].keys()]
        self.intRpTotal = len(scanList)
        for i in scanList:
            dicScan = dicRp['scans'][i]
            self.dicRpResult.update({i: dicScan['result']})

    # 안전도 백분율 리턴
    def getPercentage(self):
        return int(self.intRpPositives / self.intRpTotal * 100)

    # 각 백신별 결과 리포트를 정리하여 딕셔너리로 리턴
    def getRpResult(self):
        return self.dicRpResult

    def setVt(self, ProcessInfo):
        dicProcessList = ProcessInfo.dic_processList
