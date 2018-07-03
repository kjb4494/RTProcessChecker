import ProcessInfo

def main():
    obPInfo = ProcessInfo.ProcessInfo()
    obPInfo.createProcess('192')
    obPInfo.createProcess('193')
    obPInfo.setPcName('192', '안녕')
    obPInfo.addPcRemoteIp('192', '192.168.0.12')
    obPInfo.addPcRemoteIp('192', '192.168.0.13')
    obPInfo.addPcRemoteIp('192', '192.168.0.14')
    obPInfo.addPcRemoteIp('192', '192.168.0.15')
    obPInfo.addPcRemoteIp('193', '192.168.0.12')
    obPInfo.addPcRemoteIp('193', '192.168.0.13')
    obPInfo.addPcRemoteIp('193', '192.168.0.14')
    obPInfo.addPcRemoteIp('193', '192.168.0.15')

    for process in obPInfo.dic_processList.values():
        print(process)
        for remoteIp in process['remoteIp']:
            print(remoteIp)
        print()


if __name__ == "__main__":
    main()
