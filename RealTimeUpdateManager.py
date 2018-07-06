import OperVt
import ProcessInfo


def importVt(Form):
    obOperVt = OperVt.OperVt()
    obOperVt.setVt(Form.ProcessInfo)
    del obOperVt
    Form.vtFlag = False


# 프로세스 정보를 최신으로 갱신
def updateRTProcess(Form):
    obPcInfo = ProcessInfo.ProcessInfo()
    obPcInfo.firstScanning()
    befPcList = Form.ProcessInfo.dic_processList
    newPcList = obPcInfo.dic_processList
    delPidList = []
    for newPid in newPcList:
        # pid가 이미 존재할 경우
        if newPid in befPcList:
            # 파일 해시값이 달라졌을 경우 해당 프로세스의 vt 분석정보 초기화
            if not newPcList[newPid]['hash'] == befPcList[newPid]['hash']:
                befPcList[newPid]['vt'] = '??'
                befPcList[newPid]['vtInfo'] = {}
            # IP, Port, Dns 정보를 비교하여 wot 분석정보 초기화
            if len(newPcList[newPid]['rAddIp']) or len(befPcList[newPid]['rAddIp']):
                befPcList[newPid]['rAddIp'] = newPcList[newPid]['rAddIp']
                befPcList[newPid]['port'] = newPcList[newPid]['port']
                befPcList[newPid]['dns'] = newPcList[newPid]['dns']
                befPcList[newPid]['wot'] = newPcList[newPid]['wot']

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


def test():
    A = [1,2,3,4,5,6]
    B = [3,4,5,6,7,8,9,0]
    B = A
    print(B)


if __name__ == "__main__":
    test()
