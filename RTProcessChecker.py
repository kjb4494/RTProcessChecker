import ProcessInfo

def main():
    obPInfo = ProcessInfo.ProcessInfo()
    obPInfo.firstScanning()

    for process in obPInfo.dic_processList.values():
        print(process)


if __name__ == "__main__":
    main()
