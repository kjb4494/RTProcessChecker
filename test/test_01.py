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
        for pconn in proc.connections('inet4'):
            if len(pconn.raddr):
                (ip, port) = pconn.raddr
                if not ip == "127.0.0.1":
                    try:
                        dns = socket.gethostbyaddr(ip)
                    except:
                        dns = "Unknown"
                    print("\t{}:{}\t{}".format(ip, port, dns[0]))



if __name__ == "__main__":
    test()
