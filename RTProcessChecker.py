import ProcessInfo
import pprint

def main():
    obPInfo = ProcessInfo.ProcessInfo()
    obPInfo.firstScanning()

    pprint.pprint(obPInfo.dic_processList)


if __name__ == "__main__":
    main()
