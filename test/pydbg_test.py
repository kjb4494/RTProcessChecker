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

orgPattern = "love"
repPattern = "hate"
processName = "notepad.exe"

#""" 디버그 이벤트가 발생할 때 호출할 콜백 함수 """


def replaceString(dbg, args):
    pbuffer = dbg.read_process_memory(args[1], args[2])

    if orgPattern in pbuffer:
        print "[APIHooking] Before : %s" % pbuffer
        pbuffer = pbuffer.replace(orgPattern, repPattern)
        replace = dbg.write_process_memory(args[1], pbuffer)
        print "[APIHooking] After : %s" % dbg.read_process_memory(args[1], args[2])
    return DBG_CONTINUE

def checkDll(dbg, args):
    #pass
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

    return

def AfterHook(dbg, arg, ret):
    print("======ret addr========")
    print(hex(ret))
    return DBG_CONTINUE
#""" for문을 이용하여 윈도우에서 실행되는 모든 프로세스 ID 리스트를 얻는다. """
for (pid, name) in dbg.enumerate_processes():
    print name
    if name.lower() == processName:
        isProcess = True
        hooks = utils.hook_container()

        #""" 프로세스 핸들값 & 주소값 얻기 """
        dbg.attach(pid)
        print "Saves a process handle in self.h_process of pid[%d]" % pid
        hookAddress = dbg.func_resolve_debuggee("kernel32.dll", ""
                                                                "")

        #""" kernel32.dll의 WriteFile 함수에 중단점을 설정하고, 콜백함수 등록 """
        if hookAddress:
            hooks.add(dbg, hookAddress, 5, checkDll, None)

            print "sets a breakpoint at the designated address : 0x%08x" % hookAddress
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
