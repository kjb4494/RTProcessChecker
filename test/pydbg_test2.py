#-*- coding: utf-8 -*-
import utils, sys, struct
from pydbg import *
from pydbg.defines import *
from _msi import PID_APPNAME

'''
BOOL WINAPI WriteFile(
_In_        HANDLE hFile,
_In_        LPCVOID lpBuffer,
_In_        DWORD nNumberOfBytesToWrite,
_Out_opt_   LPDWORD lpNumberOfBytesWritten,
_Inout_opt_ LPOVERLAPPED lpOverlapped
);
'''

dbg = pydbg()
isProcess = False
processName = "notepad.exe"

def checkDll(dbg, args):

    print str(hex(hookAddress)).replace("L", "")
    print str(hex(dbg.context.Eax)).replace("L", "")
    """
    target_dll = "kernel32.dll"
    #target_function = "BaseThreadInitThunk"
    dll = windll.LoadLibrary(target_dll)
    kernel32 = windll.LoadLibrary("kernel32.dll")
    function = kernel32.GetProcAddress(dll._handle, b"LoadLibraryA")

    print("-----eax------")
    addr = str(hex(dbg.context.Eax)).replace("L", "")
    print(addr)

    #print("-----esp-----")
    #esp = str(hex(dbg.context.Esp)).replace("L", "")
    #print(esp)

    print("-----eip-----")
    eip = str(hex(dbg.context.Eip)).replace("L", "")
    print(eip)

    print("-----loadlibrary-----")
    print(hex(function))
    print("-----compare-----")

    if addr == str(hex(function)):
        print("equal-------------------!!")
    else:
        print("not equal")

"""
    return

#""" for문을 이용하여 윈도우에서 실행되는 모든 프로세스 ID 리스트를 얻는다. """
for (pid, name) in dbg.enumerate_processes():
    print name
    global hookAddress
    if name.lower() == processName:
        isProcess = True
        hooks = utils.hook_container()

        #""" 프로세스 핸들값 & 주소값 얻기 """
        dbg.attach(pid)
        print "Saves a process handle in self.h_process of pid[%d]" % pid
        hookAddress = dbg.func_resolve_debuggee("kernel32.dll", "BaseThreadInitThunk")
        print hex(hookAddress)
        eax_data = dbg.func_resolve_debuggee("kernel32.dll", "LoadLibraryW")

        #""" kernel32.dll의 WriteFile 함수에 중단점을 설정하고, 콜백함수 등록 """
        if eax_data:
            hooks.add(dbg, eax_data, 2, checkDll, None)

            print "eax_data : 0x%08x" % eax_data
            break
        else:
            print "[Error] : couldn't resolve hook address"
            sys.exit(-1)

if isProcess:
    print "wating for occurring debugger event"
    dbg.run()

else:
    print "[Error] : There in no process [%s]" % processName
    sys.exit(-1)
