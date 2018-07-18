import sys

from myPydbg.my_ctypes import *
from myPydbg.defines   import *
from myPydbg.windows_h import *
import struct

from myPydbg.pydbg_core import *
from myPydbg.pdx import *

kernel32 = windll.kernel32


class pydbg(pydbg_core):
    '''
    Extending from the core this class defines a more usable debugger objects implementing a number of features such as:

        - Register manipulation.
        - Soft (INT 3) breakpoints.
        - Memory breakpoints (page permissions).
        - Hardware breakpoints.
        - Exception / event handling call backs.
        - Pydasm (libdasm) disassembly wrapper.
        - Process memory snapshotting and restoring.
        - Endian manipulation routines.
        - Debugger hiding.
        - Function resolution.
        - "Intelligent" memory derefencing.
        - Stack/SEH unwinding.
        - Etc...
    '''

    STRING_EXPLORATON_BUF_SIZE    = 256
    STRING_EXPLORATION_MIN_LENGTH = 2

    # private variables, internal use only:
    _restore_breakpoint      = None      # breakpoint to restore
    _guarded_pages           = set()     # specific pages we set PAGE_GUARD
    _guards_active           = True      # flag specifying whether or not guard pages are active

    breakpoints              = {}        # internal breakpoint dictionary, keyed by address
    memory_breakpoints       = {}        # internal memory breakpoint dictionary, keyed by base address
    hardware_breakpoints     = {}        # internal hardware breakpoint array, indexed by slot (0-3 inclusive)
    memory_snapshot_blocks   = []        # list of memory blocks at time of memory snapshot
    memory_snapshot_contexts = []        # list of threads contexts at time of memory snapshot

    first_breakpoint         = True      # this flag gets disabled once the windows initial break is handled
    memory_breakpoint_hit    = 0         # address of hit memory breakpoint or zero on miss
                                         # designates whether or not the violation was in reaction to a memory
                                         # breakpoint hit or other unrelated event.
    hardware_breakpoint_hit  = None      # hardware breakpoint on hit or None on miss
                                         # designates whether or not the single steop event was in reaction to
                                         # a hardware breakpoint hit or other unreleated event.

    instruction              = None      # pydasm instruction object, propagated by self.disasm()
    mnemonic                 = None      # pydasm decoded instruction mnemonic, propagated by self.disasm()
    op1                      = None      # pydasm decoded 1st operand, propagated by self.disasm()
    op2                      = None      # pydasm decoded 2nd operand, propagated by self.disasm()
    op3                      = None      # pydasm decoded 3rd operand, propagated by self.disasm()

    ####################################################################################################################
    def __init__ (self, ff=True, cs=False):
        '''
        Set the default attributes. See the source if you want to modify the default creation values.

        @type  ff: Boolean
        @param ff: (Optional, Def=True) Flag controlling whether or not pydbg attaches to forked processes
        @type  cs: Boolean
        @param cs: (Optional, Def=False) Flag controlling whether or not pydbg is in client/server (socket) mode
        '''

        # private variables, internal use only:
        self._restore_breakpoint      = None      # breakpoint to restore
        self._guarded_pages           = set()     # specific pages we set PAGE_GUARD on
        self._guards_active           = True      # flag specifying whether or not guard pages are active

        self.breakpoints              = {}        # internal breakpoint dictionary, keyed by address
        self.memory_breakpoints       = {}        # internal memory breakpoint dictionary, keyed by base address
        self.hardware_breakpoints     = {}        # internal hardware breakpoint array, indexed by slot (0-3 inclusive)
        self.memory_snapshot_blocks   = []        # list of memory blocks at time of memory snapshot
        self.memory_snapshot_contexts = []        # list of threads contexts at time of memory snapshot

        self.first_breakpoint         = True      # this flag gets disabled once the windows initial break is handled
        self.memory_breakpoint_hit    = 0         # address of hit memory breakpoint or zero on miss
                                                  # designates whether or not the violation was in reaction to a memory
                                                  # breakpoint hit or other unrelated event.
        self.hardware_breakpoint_hit  = None      # hardware breakpoint on hit or None on miss
                                                  # designates whether or not the single step event was in reaction to
                                                  # a hardware breakpoint hit or other unrelated event.

        self.instruction              = None      # pydasm instruction object, propagated by self.disasm()
        self.mnemonic                 = None      # pydasm decoded instruction mnemonic, propagated by self.disasm()
        self.op1                      = None      # pydasm decoded 1st operand, propagated by self.disasm()
        self.op2                      = None      # pydasm decoded 2nd operand, propagated by self.disasm()
        self.op3                      = None      # pydasm decoded 3rd operand, propagated by self.disasm()

        # control debug/error logging.
        self.pydbg_log = lambda msg: None
        self.pydbg_err = lambda msg: sys.stderr.write("PDBG_ERR> " + msg + "\n")

        # run the core's initialization routine.
        #super(pydbg, self).__init__()
        pydbg_core.__init__(self, ff=ff, cs=cs)

    def enumerate_processes (self):
        '''
        Using the CreateToolhelp32Snapshot() API enumerate all system processes returning a list of pid / process name
        tuples.

        @see: iterate_processes()

        @rtype:  List
        @return: List of pid / process name tuples.

        Example::

            for (pid, name) in pydbg.enumerate_processes():
                if name == "test.exe":
                    break

            pydbg.attach(pid)
        '''

        self.core_log("enumerate_processes()")

        pe           = PROCESSENTRY32()
        process_list = []
        snapshot     = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0", True)

        # we *must* set the size of the structure prior to using it, otherwise Process32First() will fail.
        pe.dwSize = sizeof(PROCESSENTRY32)

        found_proc = kernel32.Process32First(snapshot, byref(pe))

        while found_proc:
            process_list.append((pe.th32ProcessID, (pe.szExeFile).decode('utf-8')))
            found_proc = kernel32.Process32Next(snapshot, byref(pe))

        kernel32.CloseHandle(snapshot)
        return process_list

    def func_resolve_debuggee (self, dll_name, func_name):
        '''
        Utility function that resolves the address of a given module / function name pair under the context of the
        debuggee.

        @author: Otto Ebeling
        @see:    func_resolve()
        @todo:   Add support for followed imports.

        @type  dll_name:  String
        @param dll_name:  Name of the DLL (case-insensitive, ex:ws2_32.dll)
        @type  func_name: String
        @param func_name: Name of the function to resolve (case-sensitive)

        @rtype:  DWORD
        @return: Address of the symbol in the target process address space if it can be resolved, None otherwise
        '''

        dll_name = dll_name.lower()

        # we can't make the assumption that all DLL names end in .dll, for example Quicktime libs end in .qtx / .qts
        # so instead of this old line:
        #     if not dll_name.endswith(".dll"):
        # we'll check for the presence of a dot and will add .dll as a conveneince.
        if not dll_name.count("."):
            dll_name += ".dll"

        for module in self.iterate_modules():
            if module.szModule.lower() == dll_name:
                base_address = module.modBaseAddr
                dos_header   = self.read_process_memory(base_address, 0x40)

                # check validity of DOS header.
                if len(dos_header) != 0x40 or dos_header[:2] != "MZ":
                    continue

                e_lfanew   = struct.unpack("<I", dos_header[0x3c:0x40])[0]
                pe_headers = self.read_process_memory(base_address + e_lfanew, 0xF8)

                # check validity of PE headers.
                if len(pe_headers) != 0xF8 or pe_headers[:2] != "PE":
                    continue

                export_directory_rva = struct.unpack("<I", pe_headers[0x78:0x7C])[0]
                export_directory_len = struct.unpack("<I", pe_headers[0x7C:0x80])[0]
                export_directory     = self.read_process_memory(base_address + export_directory_rva, export_directory_len)
                num_of_functions     = struct.unpack("<I", export_directory[0x14:0x18])[0]
                num_of_names         = struct.unpack("<I", export_directory[0x18:0x1C])[0]
                address_of_functions = struct.unpack("<I", export_directory[0x1C:0x20])[0]
                address_of_names     = struct.unpack("<I", export_directory[0x20:0x24])[0]
                address_of_ordinals  = struct.unpack("<I", export_directory[0x24:0x28])[0]
                name_table           = self.read_process_memory(base_address + address_of_names, num_of_names * 4)

                # perform a binary search across the function names.
                low  = 0
                high = num_of_names

                while low <= high:
                    # python does not suffer from integer overflows:
                    #     http://googleresearch.blogspot.com/2006/06/extra-extra-read-all-about-it-nearly.html
                    middle          = (low + high) / 2
                    current_address = base_address + struct.unpack("<I", name_table[middle*4:(middle+1)*4])[0]

                    # we use a crude approach here. read 256 bytes and cut on NULL char. not very beautiful, but reading
                    # 1 byte at a time is very slow.
                    name_buffer = self.read_process_memory(current_address, 256)
                    name_buffer = name_buffer[:name_buffer.find("\0")]

                    if name_buffer < func_name:
                        low = middle + 1
                    elif name_buffer > func_name:
                        high = middle - 1
                    else:
                        # MSFT documentation is misleading - see http://www.bitsum.com/pedocerrors.htm
                        bin_ordinal      = self.read_process_memory(base_address + address_of_ordinals + middle * 2, 2)
                        ordinal          = struct.unpack("<H", bin_ordinal)[0]   # ordinalBase has already been subtracted
                        bin_func_address = self.read_process_memory(base_address + address_of_functions + ordinal * 4, 4)
                        function_address = struct.unpack("<I", bin_func_address)[0]

                        return base_address + function_address

                # function was not found.
                return None

        # module was not found.
        return None

    def iterate_modules (self):
        '''
        A simple iterator function that can be used to iterate through all modules the target process has mapped in its
        address space. Yielded objects are of type MODULEENTRY32.

        @author: Otto Ebeling
        @see:    enumerate_modules()

        @rtype:  MODULEENTRY32
        @return: Iterated module entries.
        '''

        self.core_log("iterate_modules()")

        current_entry = MODULEENTRY32()
        snapshot      = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Module32First() will fail.
        current_entry.dwSize = sizeof(current_entry)

        if not kernel32.Module32First(snapshot, byref(current_entry)):
            return

        while 1:
            yield current_entry

            if not kernel32.Module32Next(snapshot, byref(current_entry)):
                break

        kernel32.CloseHandle(snapshot)

    def read_process_memory (self, address, length):
        '''
        Read from the debuggee process space.

        @type  address: DWORD
        @param address: Address to read from
        @type  length:  Integer
        @param length:  Length, in bytes, of data to read

        @raise pdx: An exception is raised on failure.
        @rtype:     Raw
        @return:    Read data.
        '''

        data         = ""
        read_buf     = create_string_buffer(length)
        count        = c_ulong(0)
        orig_length  = length
        orig_address = address

        # ensure we can read from the requested memory space.
        _address = address
        _length  = length

        try:
            old_protect = self.virtual_protect(_address, _length, PAGE_EXECUTE_READWRITE)
        except:
            pass

        while length:
            if not kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
                raise pdx("ReadProcessMemory(%08x, %d, read=%d)" % (address, length, count.value), True)

            data    += read_buf.raw
            length  -= count.value
            address += count.value

        # restore the original page permissions on the target memory region.
        try:
            self.virtual_protect(_address, _length, old_protect)
        except:
            pass

        return data

    def virtual_protect (self, base_address, size, protection):
        '''
        Convenience wrapper around VirtualProtectEx()

        @type  base_address: DWORD
        @param base_address: Base address of region of pages whose access protection attributes are to be changed
        @type  size:         Integer
        @param size:         Size of the region whose access protection attributes are to be changed
        @type  protection:   DWORD
        @param protection:   Memory protection to apply to the specified region

        @raise pdx: An exception is raised on failure.
        @rtype:     DWORD
        @return:    Previous access protection.
        '''

        self.core_log("VirtualProtectEx( , 0x%08x, %d, %08x, ,)" % (base_address, size, protection))

        old_protect = c_ulong(0)

        if not kernel32.VirtualProtectEx(self.h_process, base_address, size, protection, byref(old_protect)):
            raise pdx("VirtualProtectEx(%08x, %d, %08x)" % (base_address, size, protection), True)

        return old_protect.value