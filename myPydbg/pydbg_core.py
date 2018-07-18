import sys

from myPydbg.windows_h import *
from myPydbg.pdx import *

kernel32 = windll.kernel32
advapi32 = windll.advapi32

class pydbg_core(object):
    '''
    This is the core debugger class from which extended debugger functionality should be derived. This class contains:

        - The load() / attach() routines.
        - The main debug event loop.
        - Convenience wrappers for commonly used Windows API.
        - Single step toggling routine.
        - Win32 error handler wrapped around PDX.
        - Base exception / event handler routines which are meant to be overridden.
    '''

    page_size         = 0          # memory page size (dynamically resolved at run-time)
    pid               = 0          # debuggee's process id
    h_process         = None       # debuggee's process handle
    h_thread          = None       # handle to current debuggee thread
    debugger_active   = True       # flag controlling the main debugger event handling loop
    follow_forks      = False      # flag controlling whether or not pydbg attaches to forked processes
    client_server     = False      # flag controlling whether or not pydbg is in client/server mode
    callbacks         = {}         # exception callback handler dictionary
    system_dlls       = []         # list of loaded system dlls
    dirty             = False      # flag specifying that the memory space of the debuggee was modified

    # internal variables specific to the last triggered exception.
    context           = None       # thread context of offending thread
    dbg               = None       # DEBUG_EVENT
    exception_address = None       # from dbg.u.Exception.ExceptionRecord.ExceptionAddress
    write_violation   = None       # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
    violation_address = None       # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

    ####################################################################################################################
    def __init__ (self, ff=True, cs=False):
        '''
        Set the default attributes. See the source if you want to modify the default creation values.

        @type  ff: Boolean
        @param ff: (Optional, Def=True) Flag controlling whether or not pydbg attaches to forked processes
        '''

        self.page_size         = 0          # memory page size (dynamically resolved at run-time)
        self.pid               = 0          # debuggee's process id
        self.h_process         = None       # debuggee's process handle
        self.h_thread          = None       # handle to current debuggee thread
        self.debugger_active   = True       # flag controlling the main debugger event handling loop
        self.follow_forks      = ff         # flag controlling whether or not pydbg attaches to forked processes
        self.client_server     = cs         # flag controlling whether or not pydbg is in client/server mode
        self.callbacks         = {}         # exception callback handler dictionary
        self.system_dlls       = []         # list of loaded system dlls
        self.dirty             = False      # flag specifying that the memory space of the debuggee was modified

        # internal variables specific to the last triggered exception.
        self.context           = None       # thread context of offending thread
        self.dbg               = None       # DEBUG_EVENT
        self.exception_address = None       # from dbg.u.Exception.ExceptionRecord.ExceptionAddress
        self.write_violation   = None       # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
        self.violation_address = None       # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

        # control debug/error logging.
        self.core_log = lambda msg: None
        self.core_err = lambda msg: sys.stderr.write("CORE_ERR> " + msg + "\n")

        # determine the system page size.
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

        self.core_log("system page size is %d" % self.page_size)

    def attach (self, pid):
        '''
        Attach to the specified process by PID. Saves a process handle in self.h_process and prevents debuggee from
        exiting on debugger quit.

        @type  pid: Integer
        @param pid: Process ID to attach to

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg_core
        @return:    Self
        '''

        self.core_log("attaching to pid %d" % pid)

        # obtain necessary debug privileges.
        self.get_debug_privileges()

        self.pid       = pid
        self.h_process = self.open_process(pid)

        self.debug_active_process(pid)

        # allow detaching on systems that support it.
        try:
            self.debug_set_process_kill_on_exit(False)
        except:
            pass

        return self.ret_self()

    def get_debug_privileges (self):
        '''
        Obtain necessary privileges for debugging.

        @raise pdx: An exception is raised on failure.
        '''

        h_token     = HANDLE()
        luid        = LUID()
        token_state = TOKEN_PRIVILEGES()

        self.core_log("get_debug_privileges()")

        current_process = kernel32.GetCurrentProcess()

        if not advapi32.OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES, byref(h_token)):
            raise pdx("OpenProcessToken()", True)

        if not advapi32.LookupPrivilegeValueA(0, "seDebugPrivilege", byref(luid)):
            raise pdx("LookupPrivilegeValue()", True)

        token_state.PrivilegeCount = 1
        token_state.Privileges[0].Luid = luid
        token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if not advapi32.AdjustTokenPrivileges(h_token, 0, byref(token_state), 0, 0, 0):
            raise pdx("AdjustTokenPrivileges()", True)

    def open_process (self, pid):
        '''
        Convenience wrapper around OpenProcess().

        @type  pid: Integer
        @param pid: Process ID to attach to

        @raise pdx: An exception is raised on failure.
        '''

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

        if not h_process:
            raise pdx("OpenProcess(%d)" % pid, True)

        return h_process

    def debug_active_process (self, pid):
        '''
        Convenience wrapper around GetLastError() and FormatMessage(). Returns the error code and formatted message
        associated with the last error. You probably do not want to call this directly, rather look at attach().

        @type  pid: Integer
        @param pid: Process ID to attach to

        @raise pdx: An exception is raised on failure.
        '''

        if not kernel32.DebugActiveProcess(pid):
            raise pdx("DebugActiveProcess(%d)" % pid, True)

    def debug_set_process_kill_on_exit (self, kill_on_exit):
        '''
        Convenience wrapper around DebugSetProcessKillOnExit().

        @type  kill_on_exit: Bool
        @param kill_on_exit: True to kill the process on debugger exit, False to let debuggee continue running.

        @raise pdx: An exception is raised on failure.
        '''

        if not kernel32.DebugSetProcessKillOnExit(kill_on_exit):
            raise pdx("DebugActiveProcess(%s)" % kill_on_exit, True)

    def ret_self(self):
        '''
        This convenience routine exists for internal functions to call and transparently return the correct version of
        self. Specifically, an object in normal mode and a moniker when in client/server mode.

        @return: Client / server safe version of self
        '''

        if self.client_server:
            return "**SELF**"
        else:
            return self