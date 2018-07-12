# 코드 테스트를 위한 공간입니다.

import psutil
import socket
import OperInject


def test():
    procs = psutil.process_iter()
    obOperInject = OperInject.OperInject()
    for proc in procs:
        try:
            print("{}: {}\t{}".format(proc.pid, proc.name(), proc.exe()))
        except:
            print("{}: {}\tAcessDenied".format(proc.pid, proc.name()))
        else:
            p = psutil.Process(proc.pid)
            for dll in p.memory_maps():
                try:
                    print("\t{}: {}".format(dll.path, obOperInject.sys32HashTable[dll.path]))
                except:
                    print("\t[Error]\t{}".format(dll.path))


if __name__ == "__main__":
    test()
