import psutil
import hashlib

class ProcessInfo:
    def __init__(self):
        # 조회된 프로세스 정보를 저장한 딕셔너리
        self.dic_processList = {}
        '''
        분석이 완료된 dns에 대해 malware 여부를 저장하는 딕셔너리
        각 도메인은 도메인명을 키값으로 '[dnsName]': '0' or '[dnsName]': '1' or '[dnsName]': '-1' 형식의 딕셔너리로 저장된다.
        0이면 clearSite, 1이면 malwareSite, -1이면 분석이 필요한 상태
        '''
        self.gsbDataBase = {}
        '''
        DNS 정보를 검색하는데서 많은 시간을 소모한다.
        따라서 DNS 캐시테이블을 만들어 프로세스 검색 속도를 향상시킨다.
        key는 ip, value는 dns 정보가 저장된다.
        '''
        self.dnsCachTable = {}
        # 세팅을 위한 임시 저장 매개변수
        self.dns = ""
        self.gsb = ""

    def setGsb(self):
        if self.dns not in self.gsbDataBase:
            self.gsbDataBase.update({self.dns: '-1'})
            self.gsb = "??"
        else:
            if self.gsbDataBase[self.dns] == '1':
                self.gsb = "malware"
            elif self.gsbDataBase[self.dns] == '0':
                self.gsb = "safe"
            else:
                self.gsb = "??"

    def setRefGsb(self, ProcessInfo):
        if self.dns not in ProcessInfo.gsbDataBase:
            ProcessInfo.gsbDataBase.update({self.dns: '-1'})
            self.gsb = "??"
        else:
            if ProcessInfo.gsbDataBase[self.dns] == '1':
                self.gsb = "malware"
            elif ProcessInfo.gsbDataBase[self.dns] == '0':
                self.gsb = "safe"
            else:
                self.gsb = "??"

    # 모든 프로세스 최초 스캐닝
    def firstScanning(self, OperInject):
        procs = psutil.process_iter()
        for proc in procs:
            try:
                pPath = proc.exe()
                pHash = self.operFileHash(pPath)
                pVt = "??"
            except:
                pPath = "AccessDenied"
                pHash = ""
                pVt = ""
            pId = proc.pid
            # 최초 DLL 테이블 설정
            try:
                OperInject.setFirstAppDllHash(pId)
            except Exception as e:
                pass
            pName = proc.name()
            try:
                self.createProcess(pId)
            except:
                return
            else:
                self.setPcName(pId, pName)
                self.setPcPath(pId, pPath)
                self.setPcHash(pId, pHash)
                self.setPcVt(pId, pVt)
                for pconn in proc.connections('inet4'):
                    if len(pconn.raddr):
                        (ip, port) = pconn.raddr
                        (lip, lport) = pconn.laddr
                        if not ip == "127.0.0.1":
                            if ip not in self.dnsCachTable:
                                self.dnsCachTable[ip] = "??"
                                self.gsb = "??"
                                self.dns = "??"
                            else:
                                if self.dnsCachTable[ip] == "??":
                                    self.dns = "??"
                                    self.gsb = "??"
                                else:
                                    self.dns = self.dnsCachTable[ip]
                                    self.setGsb()
                            self.addPcRemoteInfo(pId, port, ip, lport)

    '''
    모든 프로세스 스캐닝. FirstScanning과 다르게
    최초 ProcessInfo 객체의 gsbDatabase를 매개변수로 둔다.
    '''

    def RTScanning(self, ProcessInfo):
        procs = psutil.process_iter()
        for proc in procs:
            try:
                pPath = proc.exe()
                pHash = self.operFileHash(pPath)
                pVt = "??"
            except:
                pPath = "AccessDenied"
                pHash = ""
                pVt = ""
            pId = proc.pid
            pName = proc.name()
            try:
                self.createProcess(pId)
            except:
                return
            else:
                self.setPcName(pId, pName)
                self.setPcPath(pId, pPath)
                self.setPcHash(pId, pHash)
                self.setPcVt(pId, pVt)
                for pconn in proc.connections('inet4'):
                    if len(pconn.raddr):
                        (ip, port) = pconn.raddr
                        (lip, lport) = pconn.laddr
                        if not ip == "127.0.0.1":
                            if ip not in ProcessInfo.dnsCachTable:
                                ProcessInfo.dnsCachTable[ip] = "??"
                                self.dns = "??"
                                self.gsb = "??"
                            else:
                                if ProcessInfo.dnsCachTable[ip] == "??":
                                    self.dns = "??"
                                    self.gsb = "??"
                                else:
                                    self.dns = ProcessInfo.dnsCachTable[ip]
                                    self.setRefGsb(ProcessInfo)
                            self.addPcRemoteInfo(pId, port, ip, lport)

    # 해당 PID를 가진 프로세스의 정보를 담기 위한 딕셔너리 메모리 확보
    def createProcess(self, pId):
        self.dic_processList.update({pId: {'name': '',
                                           'path': '',
                                           'inject': '??',
                                           'injectInfo': [],
                                           'vt': '',
                                           'vtInfo': {},
                                           'remote': [],
                                           'hash': ''}})

    def getAllInfo(self):
        return self.dic_processList

    def setPcName(self, pid, pName):
        self.dic_processList[pid]['name'] = pName

    def setPcPath(self, pid, pPath):
        self.dic_processList[pid]['path'] = pPath

    def setPcVt(self, pid, pVt):
        self.dic_processList[pid]['vt'] = pVt

    def setPcInject(self, pid, pInject):
        self.dic_processList[pid]['inject'] = pInject

    def setPcWot(self, pid, pWot):
        pass

    def addPcRemoteInfo(self, pid, pPort, pRAddIp, pLport):
        self.dic_processList[pid]['remote'].append(
            {'ip': pRAddIp, 'port': pPort, 'dns': self.dns, 'gsb': self.gsb, 'lport': pLport})

    def setPcHash(self, pid, pHash):
        self.dic_processList[pid]['hash'] = pHash

    def getPcName(self, pid):
        return self.dic_processList[pid]['name']

    # 파일의 해시를 계산
    def operFileHash(self, fPath):
        blocksize = 65536
        afile = open(fPath, 'rb')
        hasher = hashlib.md5()
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(blocksize)
        afile.close()
        return hasher.hexdigest()
