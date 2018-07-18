import sys
import signal

from myPydbg.windows_h import *
from myPydbg.pdx import *
from myPydbg.system_dll import *

kernel32 = windll.kernel32
advapi32 = windll.advapi32

import ProcessInfo

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

        print("-----------------------")
        print(current_process)
        print(TOKEN_ADJUST_PRIVILEGES)
        print(byref(h_token))
        print(byref(luid))
        print(advapi32.OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES, byref(h_token)))
        print(advapi32.LookupPrivilegeValueA(0, "SeDebugPrivilege", byref(luid)))
        print(advapi32.AdjustTokenPrivileges(h_token, 0, byref(token_state), 0, 0, 0))
        print("-----------------------")

        if not advapi32.OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES, byref(h_token)):
            raise pdx("OpenProcessToken()", True)

        if not advapi32.LookupPrivilegeValueA(0, "SeDebugPrivilege", byref(luid)):
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

    def run(self):
        self.debug_event_loop()

    def debug_event_loop(self):
        '''
        Enter the infinite debug event handling loop. This is the main loop of the debugger and is responsible for
        catching debug events and exceptions and dispatching them appropriately. This routine will check for and call
        the USER_CALLBACK_DEBUG_EVENT callback on each loop iteration. run() is an alias for this routine.

        @see: run()

        @raise pdx: An exception is raised on any exceptional conditions, such as debugger being interrupted or
        debuggee quiting.
        '''

        while self.debugger_active:
            # don't let the user interrupt us in the midst of handling a debug event.
            try:
                def_sigint_handler = None
                def_sigint_handler = signal.signal(signal.SIGINT, self.sigint_handler)
            except:
                pass

            # if a user callback was specified, call it.
            if self.callbacks in USER_CALLBACK_DEBUG_EVENT:
                # user callbacks do not / should not access debugger or contextual information.
                self.dbg = self.context = None
                self.callbacks[USER_CALLBACK_DEBUG_EVENT](self)

            # iterate through a debug event.
            self.debug_event_iteration()

            # resume keyboard interruptability.
            if def_sigint_handler:
                signal.signal(signal.SIGINT, def_sigint_handler)

        # if the process is still around, detach (if that is supported on the current system) from it.
        try:
            self.detach()
        except:
            pass

    def sigint_handler (self, signal_number, stack_frame):
        '''
        Interrupt signal handler. We override the default handler to disable the run flag and exit the main
        debug event loop.

        @type  signal_number:
        @param signal_number:
        @type  stack_frame:
        @param stack_frame:
        '''

        self.set_debugger_active(False)

    def set_debugger_active (self, enable):
        '''
        Enable or disable the control flag for the main debug event loop. This is a convenience shortcut over set_attr.

        @type  enable: Boolean
        @param enable: Flag controlling the main debug event loop.
        '''

        self.core_log("setting debug event loop flag to %s" % enable)

        self.debugger_active = enable

    def debug_event_iteration (self):
        '''
        Check for and process a debug event.
        '''

        continue_status = DBG_CONTINUE
        dbg             = DEBUG_EVENT()

        # wait for a debug event.
        if kernel32.WaitForDebugEvent(byref(dbg), 100):
            # grab various information with regards to the current exception.
            self.h_thread          = self.open_thread(dbg.dwThreadId)
            self.context           = self.get_thread_context(self.h_thread)
            self.dbg               = dbg
            self.exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress
            self.write_violation   = dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
            self.violation_address = dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

            if dbg.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                continue_status = self.event_handler_create_process()
                self.close_handle(self.dbg.u.CreateProcessInfo.hFile)

            elif dbg.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
                continue_status = self.event_handler_create_thread()

            elif dbg.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                continue_status = self.event_handler_exit_process()

            elif dbg.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT:
                continue_status = self.event_handler_exit_thread()

            elif dbg.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT:
                continue_status = self.event_handler_load_dll()
                self.close_handle(self.dbg.u.LoadDll.hFile)

            elif dbg.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT:
                continue_status = self.event_handler_unload_dll()

            # an exception was caught.
            elif dbg.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                ec = dbg.u.Exception.ExceptionRecord.ExceptionCode

                self.core_log("debug_event_loop() exception: %08x" % ec)

                # call the internal handler for the exception event that just occured.
                if ec == EXCEPTION_ACCESS_VIOLATION:
                    continue_status = self.exception_handler_access_violation()
                elif ec == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                elif ec == EXCEPTION_GUARD_PAGE:
                    continue_status = self.exception_handler_guard_page()
                elif ec == EXCEPTION_SINGLE_STEP:
                    continue_status = self.exception_handler_single_step()
                # generic callback support.
                elif self.callbacks in ec:
                    continue_status = self.callbacks[ec](self)
                # unhandled exception.
                else:
                    self.core_log("TID:%04x caused an unhandled exception (%08x) at %08x" % (self.dbg.dwThreadId, ec, self.exception_address))
                    continue_status = DBG_EXCEPTION_NOT_HANDLED

            # if the memory space of the debuggee was tainted, flush the instruction cache.
            # from MSDN: Applications should call FlushInstructionCache if they generate or modify code in memory.
            #            The CPU cannot detect the change, and may execute the old code it cached.
            if self.dirty:
                kernel32.FlushInstructionCache(self.h_process, 0, 0)

            # close the opened thread handle and resume executing the thread that triggered the debug event.
            self.close_handle(self.h_thread)
            kernel32.ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, continue_status)

    def event_handler_create_thread (self):
        '''
        This is the default CREATE_THREAD_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_CONTINUE

    def event_handler_exit_process (self):
        '''
        This is the default EXIT_PROCESS_DEBUG_EVENT handler.

        @raise pdx: An exception is raised to denote process exit.
        '''

        self.set_debugger_active(False)
        self.close_handle(self.h_process)

        self.pid = self.h_process = None

        return DBG_CONTINUE

    def event_handler_exit_thread (self):
        '''
        This is the default EXIT_THREAD_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_CONTINUE

    def event_handler_load_dll (self):
        '''
        This is the default LOAD_DLL_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        dll = system_dll(self.dbg.u.LoadDll.hFile, self.dbg.u.LoadDll.lpBaseOfDll)
        self.system_dlls.append(dll)

        return DBG_CONTINUE

    def event_handler_unload_dll (self):
        '''
        This is the default UNLOAD_DLL_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        base     = self.dbg.u.UnloadDll.lpBaseOfDll
        unloaded = None

        for system_dll in self.system_dlls:
            if system_dll.base == base:
                unloaded = system_dll
                break

        if not unloaded:
            #raise pdx("Unable to locate DLL that is being unloaded from %08x" % base, False)
            pass
        else:
            self.system_dlls.remove(unloaded)

        return DBG_CONTINUE

    def open_thread (self, thread_id):
        '''
        Convenience wrapper around OpenThread().

        @type  thread_id: Integer
        @param thread_id: ID of thread to obtain handle to

        @raise pdx: An exception is raised on failure.
        '''

        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

        if not h_thread:
            raise pdx("OpenThread(%d)" % thread_id, True)

        return h_thread

    def get_thread_context (self, thread_handle, thread_id=0):
        '''
        Convenience wrapper around GetThreadContext(). Can obtain a thread context via a handle or thread id.

        @type  thread_handle: HANDLE
        @param thread_handle: (Optional) Handle of thread to get context of
        @type  thread_id:     Integer
        @param thread_id:     (Optional, Def=0) ID of thread to get context of

        @raise pdx: An exception is raised on failure.
        @rtype:     CONTEXT
        @return:    Thread CONTEXT on success.
        '''

        self.core_log("get_thread_context()")

        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        # if a thread handle was not specified, get one from the thread id.
        if not thread_handle:
            h_thread = self.open_thread(thread_id)
        else:
            h_thread = thread_handle

        if not kernel32.GetThreadContext(h_thread, byref(context)):
            raise pdx("GetThreadContext()", True)

        # if we had to resolve the thread handle, close it.
        if not thread_handle:
            kernel32.CloseHandle(h_thread)

        return context

    def exception_handler_access_violation (self):
        '''
        This is the default EXCEPTION_ACCESS_VIOLATION handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_EXCEPTION_NOT_HANDLED

    def exception_handler_breakpoint (self):
        '''
        This is the default EXCEPTION_BREAKPOINT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_EXCEPTION_NOT_HANDLED

    def exception_handler_guard_page (self):
        '''
        This is the default EXCEPTION_GUARD_PAGE handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_EXCEPTION_NOT_HANDLED

    def exception_handler_single_step (self):
        '''
        This is the default EXCEPTION_SINGLE_STEP handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_EXCEPTION_NOT_HANDLED

    def event_handler_create_process (self):
        '''
        This is the default CREATE_PROCESS_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_CONTINUE

    def close_handle (self, handle):
        '''
        Convenience wraper around kernel32.CloseHandle().

        @type  handle: Handle
        @param handle: Handle to close

        @rtype:  Bool
        @return: Return value from CloseHandle().
        '''

        return kernel32.CloseHandle(handle)

    def detach (self):
        '''
        Detach from debuggee.
        '''

        self.core_log("detaching from debuggee")

        # if we're not attached to a process, we have nothing to do.
        if not self.pid:
            return

        self.cleanup()
        self.set_debugger_active(False)

        # try to detach from the target process if the API is available on the current platform.
        try:
            kernel32.DebugActiveProcessStop(self.pid)
        except:
            pass

    def cleanup (self):
        '''
        Clean up after ourselves.

        @rtype:     pydbg_core
        @return:    Self
        '''

        self.core_log("pydbg_core cleaning up")

        # ensure no threads are suspended or in single step mode.
        for thread_id in self.enumerate_threads():
            self.resume_thread(thread_id)

            try:
                handle = self.open_thread(thread_id)
                self.single_step(False, handle)
                self.close_handle(handle)
            except:
                pass

        return self.ret_self()

    def enumerate_threads (self):
        '''
        Using the CreateToolhelp32Snapshot() API enumerate all system threads returning a list of thread IDs that
        belong to the debuggee.

        @see: iterate_threads()

        @rtype:  List
        @return: List of thread IDs belonging to the debuggee.

        Example::
            for thread_id in self.enumerate_threads():
                context = self.get_thread_context(None, thread_id)
        '''

        self.core_log("enumerate_threads()")

        thread_entry     = THREADENTRY32()
        debuggee_threads = []
        snapshot         = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Thread32First() will fail.
        thread_entry.dwSize = sizeof(thread_entry)

        success = kernel32.Thread32First(snapshot, byref(thread_entry))

        while success:
            if thread_entry.th32OwnerProcessID == self.pid:
                debuggee_threads.append(thread_entry.th32ThreadID)

            success = kernel32.Thread32Next(snapshot, byref(thread_entry))

        kernel32.CloseHandle(snapshot)
        return debuggee_threads

    def resume_thread (self, thread_id):
        '''
        Resume the specified thread.

        @type  thread_id: DWORD
        @param thread_id: ID of thread to resume

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg_core
        @return:    Self
        '''

        self.core_log("resuming thread: %08x" % thread_id)

        thread_handle = self.open_thread(thread_id)

        if kernel32.ResumeThread(thread_handle) == -1:
            raise pdx("ResumeThread()", True)

        kernel32.CloseHandle(thread_handle)

        return self.ret_self()

    def single_step (self, enable, thread_handle=None):
        '''
        Enable or disable single stepping in the specified thread or self.h_thread if a thread handle is not specified.

        @type  enable:        Bool
        @param enable:        True to enable single stepping, False to disable
        @type  thread_handle: Handle
        @param thread_handle: (Optional, Def=None) Handle of thread to put into single step mode

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg_core
        @return:    Self
        '''

        self.core_log("single_step(%s)" % enable)

        if not thread_handle:
            thread_handle = self.h_thread

        context = self.get_thread_context(thread_handle)

        if enable:
            # single step already enabled.
            if context.EFlags & EFLAGS_TRAP:
                return self.ret_self()

            context.EFlags |= EFLAGS_TRAP
        else:
            # single step already disabled:
            if not context.EFlags & EFLAGS_TRAP:
                return self.ret_self()

            context.EFlags = context.EFlags & (0xFFFFFFFFFF ^ EFLAGS_TRAP)

        self.set_thread_context(context, thread_handle=thread_handle)

        return self.ret_self()

    def set_thread_context (self, context, thread_handle=None, thread_id=0):
        '''
        Convenience wrapper around SetThreadContext(). Can set a thread context via a handle or thread id.

        @type  thread_handle: HANDLE
        @param thread_handle: (Optional) Handle of thread to get context of
        @type  context:       CONTEXT
        @param context:       Context to apply to specified thread
        @type  thread_id:     Integer
        @param thread_id:     (Optional, Def=0) ID of thread to get context of

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg_core
        @return:    Self
        '''

        # if neither a thread handle or thread id were specified, default to the internal one.
        if not thread_handle and not thread_id:
            h_thread = self.h_thread

        # if a thread handle was not specified, get one from the thread id.
        elif not thread_handle:
            h_thread = self.open_thread(thread_id)

        # use the specified thread handle.
        else:
            h_thread = thread_handle

        if not kernel32.SetThreadContext(h_thread, byref(context)):
            raise pdx("SetThreadContext()", True)

        # if we had to resolve the thread handle, close it.
        if not thread_handle and thread_id:
            kernel32.CloseHandle(h_thread)

        return self.ret_self()