import psutil
import socket
from ctypes import *
from ctypes.wintypes import *

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


class ProcessInfo:
    def __init__(self):
        self.dic_processList = {}

    def firstScanning(self):
        procs = psutil.process_iter(attrs=['pid', 'name', 'connections'])
        enable_privilege('SeDebugPrivilege')
        for proc in procs:
            procDic = proc.as_dict(attrs=['pid', 'name', 'connections'])
            try:
                pPath = proc.exe()
            except:
                pPath = "AccessDenied"
            pId = procDic['pid']
            pName = procDic['name']
            self.createProcess(pId)
            self.setPcName(pId, pName)
            self.setPcPath(pId, pPath)
            for pconn in procDic['connections']:
                if len(pconn.raddr):
                    (ip, port) = pconn.raddr
                    if not ip == "127.0.0.1":
                        try:
                            dns = socket.gethostbyaddr(ip)[0]
                        except:
                            dns = "Unknown"
                        self.addPcRemoteInfo(pId, port, ip, dns)

    def createProcess(self, pId):
        try:
            self.dic_processList.update({pId: {'name': '',
                                               'path': '',
                                               'inject': '??',
                                               'vt': '??',
                                               'wot': '??',
                                               'rAddIp': [],
                                               'port': [],
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

    def addPcRemoteInfo(self, pid, pPort, pRAddIp, pDns):
        self.dic_processList[pid]['port'].append(pPort)
        self.dic_processList[pid]['rAddIp'].append(pRAddIp)
        self.dic_processList[pid]['dns'].append(pDns)

    def getPcName(self, pid):
        return self.dic_processList[pid]['name']
