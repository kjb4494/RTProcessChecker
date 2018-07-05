import ProcessInfo
import OperVt
import pprint


def main():
    obPInfo = ProcessInfo.ProcessInfo()
    obPInfo.firstScanning()
    obOperVt = OperVt.OperVt()
    obOperVt.setVt(obPInfo)
    pprint.pprint(obPInfo.dic_processList)


if __name__ == "__main__":
    main()
