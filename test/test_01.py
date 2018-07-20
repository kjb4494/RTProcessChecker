import psutil
import ProcessInfo
import pprint
from win32api import *
from ctypes import *
from ctypes.wintypes import *


def test():
    ProcessInfo.enable_privilege('SeDebugPrivilege')
    procs = psutil.process_iter()
    kernel32 = windll.kernel32
    print(kernel32.Process.GetCurrentProcess().Threads)
    # for proc in procs:
    #     try:
    #         pprint.pprint(proc.threads())
    #         print("{}: {}\t{}".format(proc.pid, proc.name(), proc.exe()))
    #     except:
    #         print("{}: {}\tAcessDenied".format(proc.pid, proc.name()))
    #     else:
    #         p = psutil.Process(proc.pid)
    #         print(p.memory_info_ex())
    #         for dll in p.memory_maps(grouped=False):
    #             try:
    #                 print("\t{}".format(dll))
    #             except:
    #                 print("\t[Error]\t{}".format(dll.path))


if __name__ == "__main__":
    test()
