import os, sys, time
from win32com.client import GetObject


def getProcessesList():
    processesList = []
    getObj = GetObject('winmgmts:')
    processes = getObj.InstancesOf('win32_Process')
    for ps in processes:
        processesList.append(ps.Properties_('Name').value)
    return "\n".join(processesList)


def main():
    print(getProcessesList())


if __name__ == "__main__":
    main()
