import ProcessInfo
import OperInject
import sys
import QtFrame
from PyQt5.QtWidgets import QApplication
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


def ProcessCheckerView(ProcessInfo, OperInject):
    app = QApplication(sys.argv)
    form = QtFrame.Form()
    form.init_widget(ProcessInfo, OperInject)
    form.show()
    exit(app.exec_())


def main():
    enable_privilege('SeDebugPrivilege')
    obOperInject = OperInject.OperInject()
    obPInfo = ProcessInfo.ProcessInfo()
    obPInfo.firstScanning(obOperInject)
    ProcessCheckerView(obPInfo, obOperInject)


if __name__ == "__main__":
    main()
