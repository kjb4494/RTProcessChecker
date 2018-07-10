import psutil
import socket
import hashlib
from ctypes import *
from ctypes.wintypes import *

# --------------------------------------------------------------
# 프로세스의 파일 경로 조회 권한을 가져오기 위한 작업
# --------------------------------------------------------------

kernel32 = WinDLL('kernel32', use_last_error=True)
advapi32 = WinDLL('advapi32', use_last_error=True)

SE_PRIVILEGE_ENABLED = 0x00000002
TOKEN_ALL_ACCESS = 0x000F0000 | 0x01FF


class LUID(Structure):
    _fields_ = (('LowPart', DWORD),
                ('HighPart', LONG))


class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = (('Luid', LUID),
                ('Attributes', DWORD))


class TOKEN_PRIVILEGES(Structure):
    _fields_ = (('PrivilegeCount', DWORD),
                ('Privileges', LUID_AND_ATTRIBUTES * 1))

    def __init__(self, PrivilegeCount=1, *args):
        super(TOKEN_PRIVILEGES, self).__init__(PrivilegeCount, *args)


PDWORD = POINTER(DWORD)
PHANDLE = POINTER(HANDLE)
PLUID = POINTER(LUID)
PTOKEN_PRIVILEGES = POINTER(TOKEN_PRIVILEGES)


def errcheck_bool(result, func, args):
    if not result:
        raise WinError(get_last_error())
    return args


kernel32.CloseHandle.argtypes = (HANDLE,)

kernel32.GetCurrentProcess.errcheck = errcheck_bool
kernel32.GetCurrentProcess.restype = HANDLE

# https://msdn.microsoft.com/en-us/library/aa379295
advapi32.OpenProcessToken.errcheck = errcheck_bool
advapi32.OpenProcessToken.argtypes = (
    HANDLE,  # _In_  ProcessHandle
    DWORD,  # _In_  DesiredAccess
    PHANDLE)  # _Out_ TokenHandle

# https://msdn.microsoft.com/en-us/library/aa379180
advapi32.LookupPrivilegeValueW.errcheck = errcheck_bool
advapi32.LookupPrivilegeValueW.argtypes = (
    LPCWSTR,  # _In_opt_ lpSystemName
    LPCWSTR,  # _In_     lpName
    PLUID)  # _Out_    lpLuid

# https://msdn.microsoft.com/en-us/library/aa375202
advapi32.AdjustTokenPrivileges.errcheck = errcheck_bool
advapi32.AdjustTokenPrivileges.argtypes = (
    HANDLE,  # _In_      TokenHandle
    BOOL,  # _In_      DisableAllPrivileges
    PTOKEN_PRIVILEGES,  # _In_opt_  NewState
    DWORD,  # _In_      BufferLength
    PTOKEN_PRIVILEGES,  # _Out_opt_ PreviousState
    PDWORD)  # _Out_opt_ ReturnLength


def enable_privilege(privilege):
    hToken = HANDLE()
    luid = LUID()
    advapi32.LookupPrivilegeValueW(None, privilege, byref(luid))
    try:
        advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                  TOKEN_ALL_ACCESS,
                                  byref(hToken))
        tp = TOKEN_PRIVILEGES()
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(hToken, False,
                                       byref(tp),
                                       sizeof(tp),
                                       None, None)
    finally:
        if hToken:
            kernel32.CloseHandle(hToken)


# --------------------------------------------------------------

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

    # 모든 프로세스 최초 스캐닝
    def firstScanning(self):
        procs = psutil.process_iter()
        enable_privilege('SeDebugPrivilege')
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
                        if not ip == "127.0.0.1":
                            try:
                                dns = socket.gethostbyaddr(ip)[0]
                            except:
                                dns = "Unknown"
                                gsb = "-"
                            else:
                                if dns not in self.gsbDataBase:
                                    self.gsbDataBase.update({dns: '-1'})
                                    gsb = "??"
                                else:
                                    if self.gsbDataBase[dns] == '1':
                                        gsb = "malware"
                                    elif self.gsbDataBase[dns] == '0':
                                        gsb = "safe"
                                    else:
                                        gsb = "??"
                            self.addPcRemoteInfo(pId, port, ip, dns, gsb)
    '''
    모든 프로세스 스캐닝. FirstScanning과 다르게
    최초 ProcessInfo 객체의 gsbDatabase를 매개변수로 둔다.
    '''
    def RTScanning(self, gsbDatabase):
        procs = psutil.process_iter()
        enable_privilege('SeDebugPrivilege')
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
                        if not ip == "127.0.0.1":
                            try:
                                dns = socket.gethostbyaddr(ip)[0]
                            except:
                                dns = "Unknown"
                                gsb = "-"
                            else:
                                if dns not in gsbDatabase:
                                    gsbDatabase.update({dns: '-1'})
                                    gsb = "??"
                                else:
                                    if gsbDatabase[dns] == '1':
                                        gsb = "malware"
                                    elif gsbDatabase[dns] == '0':
                                        gsb = "safe"
                                    else:
                                        gsb = "??"
                            self.addPcRemoteInfo(pId, port, ip, dns, gsb)

    # 해당 PID를 가진 프로세스의 정보를 담기 위한 딕셔너리 메모리 확보
    def createProcess(self, pId):
        self.dic_processList.update({pId: {'name': '',
                                           'path': '',
                                           'inject': '??',
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

    def addPcRemoteInfo(self, pid, pPort, pRAddIp, pDns, pGsb):
        self.dic_processList[pid]['remote'].append({'ip': pRAddIp, 'port': pPort, 'dns': pDns, 'gsb': pGsb})

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
