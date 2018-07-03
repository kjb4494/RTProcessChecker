import win32pdh
from win32com.server.exception import COMException
import psutil
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


def disable_privilege(privilege):
    hToken = HANDLE()
    luid = LUID()
    advapi32.LookupPrivilegeValueW(None, privilege, byref(luid))
    try:
        advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                  TOKEN_ALL_ACCESS,
                                  byref(hToken))
        tp = TOKEN_PRIVILEGES()
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = 0
        advapi32.AdjustTokenPrivileges(hToken, False,
                                       byref(tp),
                                       sizeof(tp),
                                       None, None)
    finally:
        if hToken:
            kernel32.CloseHandle(hToken)


class pyperf:
    # COM attributes.
    _reg_clsid_ = '{763AE791-1D6B-11D4-A38B-00902798B22B}'
    # guid for your class in registry
    _reg_desc_ = "get process list and ids"
    _reg_progid_ = "PyPerf.process"  # The progid for this class

    _public_methods_ = ['procids', 'proclist']  # names of callable methods

    def __init__(self):
        self.object = 'process'
        self.item = 'ID Process'

    def proclist(self):
        try:
            junk, instances = win32pdh.EnumObjectItems(None, None, self.object, win32pdh.PERF_DETAIL_WIZARD)
            psNames = []
            for psName in instances:
                psNames.append(psName + '.exe')
            return psNames
        except:
            raise COMException("Problem getting process list")

    def procids(self):
        # each instance is a process, you can have multiple processes w/same name
        instances = self.proclist()
        proc_ids = []
        proc_dict = {}
        for instance in instances:
            if instance in proc_dict:
                proc_dict[instance] = proc_dict[instance] + 1
            else:
                proc_dict[instance] = 0
        for instance, max_instances in proc_dict.items():
            for inum in range(max_instances + 1):
                try:
                    hq = win32pdh.OpenQuery()  # initializes the query handle
                    path = win32pdh.MakeCounterPath((None, self.object, instance, None, inum, self.item))
                    counter_handle = win32pdh.AddCounter(hq, path)  # convert counter path to counter handle
                    win32pdh.CollectQueryData(hq)  # collects data for the counter
                    type, val = win32pdh.GetFormattedCounterValue(counter_handle, win32pdh.PDH_FMT_LONG)
                    proc_ids.append(instance + '\t' + str(val))
                    win32pdh.CloseQuery(hq)
                except:
                    raise COMException("Problem getting process id")

        proc_ids.sort()
        return proc_ids


if __name__ == '__main__':
    pyperfOb = pyperf()
    print(pyperfOb.proclist())
    # print("\n".join(pyperfOb.procids()))

    system_process_names = pyperfOb.proclist()
    system_processes = []

    print('SeDebugPrivilege Enabled')
    enable_privilege('SeDebugPrivilege')
    for proc in psutil.process_iter():
        try:
            name = proc.name().lower()
            path = proc.exe()
        except psutil.AccessDenied:
            name = ''
            print('{:04d} {} ACCESS_DENIED'.format(proc.pid, name))
            continue
        if name in system_process_names:
            system_process_names.remove(name)
            system_processes.append(proc)
            print('{:04d} {} {}'.format(proc.pid, name, path))