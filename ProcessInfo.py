class ProcessInfo:
    def __init__(self):
        self.dic_processList = {}

    def createProcess(self, pid):
        try:
            self.dic_processList.update({pid: {'name': '',
                                               'path': '',
                                               'inject': '',
                                               'vt': '',
                                               'wot': '',
                                               'remoteIp': [],
                                               'dns': []}})
        except:
            return

    def getAllInfo(self):
        return self.dic_processList

    def setPcName(self, pid, pName):
        self.dic_processList[pid]['name'] = pName

    def setPcPath(self, pid, pPath):
        self.dic_processList[pid]['path'] = pPath

    def setPcInject(self, pid, pInject):
        self.dic_processList[pid]['inject'] = pInject

    def setPcVt(self, pid, pVt):
        self.dic_processList[pid]['vt'] = pVt

    def setPcWot(self, pid, pWot):
        self.dic_processList[pid]['wot'] = pWot

    # 임시 함수
    def addPcRemoteIp(self, pid, pRemoteIp):
        self.dic_processList[pid]['remoteIp'].append(pRemoteIp)

    def getPcName(self, pid):
        return self.dic_processList[pid]['name']