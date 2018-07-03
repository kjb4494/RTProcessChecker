import psutil
import socket

rows = []
lc = psutil.net_connections('inet')

for c in lc:

    if len(c.raddr):
        (ip, port) = c.raddr
        if not (ip == '127.0.0.1' or ip == '::1'):
            if c.type == socket.SOCK_STREAM:
                proto_s = 'tcp'
            elif c.type == socket.SOCK_DGRAM:
                proto_s = 'udp'
            else:
                continue
            pid_s = str(c.pid) if c.pid else '(unknown)'
            try:
                dns = socket.gethostbyaddr(ip)
            except:
                pass
            else:
                msg = 'PID {} is listening on port {}/{} for IP:{} / DNS:{}.'
                msg = msg.format(pid_s, port, proto_s, ip, dns[0])
                print(msg)

