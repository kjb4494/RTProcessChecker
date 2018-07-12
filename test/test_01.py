# 코드 테스트를 위한 공간입니다.

import psutil
import socket


def test():
    print("hello Wolrd!")
    procs = psutil.process_iter()
    for proc in procs:
        try:
            print("{}: {}\t{}".format(proc.pid, proc.name(), proc.exe()))
        except:
            print("{}: {}\tAcessDenied".format(proc.pid, proc.name()))
        else:
            p = psutil.Process(proc.pid)
            for dll in p.memory_maps():
                print("\t{}".format(dll.path))


if __name__ == "__main__":
    test()
