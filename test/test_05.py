from ctypes import *
from ctypes.wintypes import *
import sys


# const variable
# Establish rights and basic options needed for all process declartion / iteration
TH32CS_SNAPPROCESS = 2
STANDARD_RIGHTS_REQUIRED = 0x000F0000
SYNCHRONIZE = 0x00100000
PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPTHREAD = 0x00000004

#class MODULEENTRY32(Structure):
#    _fields_ = [ ( 'dwSize' , DWORD ) ,
#                ( 'th32ModuleID' , DWORD ),
#                ( 'th32ProcessID' , DWORD ),
#                ( 'GlblcntUsage' , DWORD ),
#                ( 'ProccntUsage' , DWORD ) ,
#                ( 'modBaseAddr' , LONG ) ,
#                ( 'modBaseSize' , DWORD ) ,
#                ( 'hModule' , HMODULE ) ,
#                ( 'szModule' , c_char * 256 ),
#                ( 'szExePath' , c_char * 260 ) ]


class MODULEENTRY32(Structure):
    _fields_ = [ ( 'dwSize' , c_long ) ,
                ( 'th32ModuleID' , c_long ),
                ( 'th32ProcessID' , c_long ),
                ( 'GlblcntUsage' , c_long ),
                ( 'ProccntUsage' , c_long ) ,
                ( 'modBaseAddr' , c_long ) ,
                ( 'modBaseSize' , c_long ) ,
                ( 'hModule' , c_void_p ) ,
                ( 'szModule' , c_char * 256 ),
                ( 'szExePath' , c_char * 260 ) ]


CreateToolhelp32Snapshot= windll.kernel32.CreateToolhelp32Snapshot
Process32First = windll.kernel32.Process32First
Process32Next = windll.kernel32.Process32Next
Module32First = windll.kernel32.Module32First
Module32Next = windll.kernel32.Module32Next
GetLastError = windll.kernel32.GetLastError
OpenProcess = windll.kernel32.OpenProcess
GetPriorityClass = windll.kernel32.GetPriorityClass
CloseHandle = windll.kernel32.CloseHandle


try:
    ProcessID=11216
    hModuleSnap = DWORD
    me32 = MODULEENTRY32()
    me32.dwSize = sizeof( MODULEENTRY32 )
    #me32.dwSize = 5000
    hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, ProcessID )
    ret = Module32First( hModuleSnap, pointer(me32) )
    if ret == 0 :
        print('ListProcessModules() Error on Module32First[%d]' % GetLastError())
        CloseHandle( hModuleSnap )
    global PROGMainBase
    PROGMainBase=False
    while ret :
        print("--------------------------------------------")
        print(me32.dwSize)
        print(me32.th32ModuleID)
        print(me32.th32ProcessID)
        print(me32.GlblcntUsage)
        print(me32.ProccntUsage)
        print(hex(me32.modBaseAddr))
        print(me32.modBaseSize)
        print(me32.hModule)
        print(me32.szModule)
        print(me32.szExePath)
        ret = Module32Next( hModuleSnap , pointer(me32) )
    CloseHandle( hModuleSnap )



except:
    print("Error in ListProcessModules")