import OperVt
import ProcessInfo
import OperWot


def importVt(Form):
    obOperVt = OperVt.OperVt()
    obOperVt.setVt(Form.ProcessInfo)
    del obOperVt
    Form.vtFlag = False


# 프로세스 정보를 최신으로 갱신
def updateRTProcess(Form):
    befPcList = Form.ProcessInfo.dic_processList
    obPcInfo = ProcessInfo.ProcessInfo()
    obPcInfo.RTScanning(Form.ProcessInfo.gsbDataBase)
    newPcList = obPcInfo.dic_processList
    delPidList = []
    for newPid in newPcList:
        # pid가 이미 존재할 경우
        if newPid in befPcList:
            # 파일 해시값이 달라졌을 경우 해당 프로세스의 vt 분석정보 초기화
            if not newPcList[newPid]['hash'] == befPcList[newPid]['hash']:
                befPcList[newPid]['vt'] = '??'
                befPcList[newPid]['vtInfo'] = {}
            # IP, Port, Dns 정보를 비교하여 gsb 분석정보 초기화
            if len(newPcList[newPid]['remote']) or len(befPcList[newPid]['remote']):
                befPcList[newPid]['remote'] = newPcList[newPid]['remote']

        # pid가 새로 생긴건 갱신
        else:
            Form.ProcessInfo.createProcess(newPid)
            befPcList[newPid] = newPcList[newPid]
    # 죽은 프로세스는 삭제
    for befPid in befPcList:
        if befPid not in newPcList:
            delPidList.append(befPid)
    for i in delPidList:
        del befPcList[i]
    del obPcInfo  # 객체 FREE
    Form.psFlag = False


def updateGsb(Form):
    obOperWot = OperWot.OperWot()
    try:
        for dns, value in Form.ProcessInfo.gsbDataBase.items():
            if value != '-1':
                continue
            if obOperWot.isMalwareUrl(dns):
                Form.ProcessInfo.gsbDataBase[dns] = '1'
            else:
                Form.ProcessInfo.gsbDataBase[dns] = '0'
    except Exception as e:
        print(e)
        return
    finally:
        del obOperWot
        Form.gsbFlag = False


def test():
    dicA = {'1': '111',
            '2': '222',
            '3': '333'}
    for key, value in dicA.items():
        value = 111
        print("{}: {}".format(key, value))


if __name__ == "__main__":
    test()
