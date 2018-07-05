import ProcessInfo
import OperVt
import pprint

def main():
    obPInfo = ProcessInfo.ProcessInfo()
    obPInfo.firstScanning()

    pprint.pprint(obPInfo.dic_processList)
    obOperVt = OperVt.OperVt()
    obOperVt.setVt(obPInfo)


if __name__ == "__main__":
    main()
