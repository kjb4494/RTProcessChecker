# -*- coding: utf-8 -*-
from myPydbg.pydbg import *
from myPydbg.hooking import *


dbg = pydbg()
isProcess = False
processName = "notepad.exe"

"""
HMODULE WINAPI LoadLibrary(
  _In_ LPCTSTR lpFileName
);
"""


def EntryHook(dbg, args):
    if str(hex(hookAddress)).replace("L", "") == str(hex(dbg.context.Eax)).replace("L", ""):
        print(str(hex(hookAddress)).replace("L", ""))
        print(str(hex(dbg.context.Eax)).replace("L", ""))
        dbg.debugger_active = False
        print("루프 사라짐")

    return


# """ for문을 이용하여 윈도우에서 실행되는 모든 프로세스 ID 리스트를 얻는다. """
for (pid, name) in dbg.enumerate_processes():
    print(name)
    global hookAddress
    if name.lower() == processName:
        isProcess = True
        hooks = hook_container()

        # """ 프로세스 핸들값 & 주소값 얻기 """
        dbg.attach(pid)
        print("Saves a process handle in self.h_process of pid[%d]" % pid)

        target_dll = "kernel32.dll"
        target_function = "BaseThreadInitThunk"
        dll = windll.LoadLibrary(target_dll)
        kernel32 = windll.LoadLibrary("kernel32.dll")
        hookAddress = kernel32.GetProcAddress(dll._handle, b"BaseThreadInitThunk")

        LL_hookAddress = dbg.func_resolve_debuggee("kernel32.dll", "LoadLibraryW")

        # """ kernel32.dll의 WriteFile 함수에 중단점을 설정하고, 콜백함수 등록 """
        if LL_hookAddress:
            hooks.add(dbg, LL_hookAddress, 1, EntryHook, None)
            print("LL_hookAddress : 0x%08x" % LL_hookAddress)
            break
        else:
            print("[Error] : couldn't resolve hook address")
            sys.exit(-1)

if isProcess:
    print("wating for occurring debugger event")
    dbg.run()

else:
    print("[Error] : There in no process [%s]" % processName)
    sys.exit(-1)
