import OperVt
import ProcessInfo
import OperWot
import OperInject
import time


def importVt(Form):
    obOperVt = OperVt.OperVt()
    obOperVt.setVt(Form.ProcessInfo)
    del obOperVt
    Form.vtFlag = False


# 프로세스 정보를 최신으로 갱신
def updateRTProcess(Form):
    befPcList = Form.ProcessInfo.dic_processList
    obPcInfo = ProcessInfo.ProcessInfo()
    while True:
        try:
            obPcInfo.RTScanning(Form.ProcessInfo)
        except Exception as e:
            print("error!! --> {}".format(e))
            continue
        else:
            break
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
            # inject 여부 검사
            try:
                injectCheck = Form.OperInject.isInjected(newPid)
                if type(injectCheck) == int:
                    Form.ProcessInfo.dic_processList[newPid]['inject'] = str(Form.OperInject.isInjected(newPid))
            # AccessDenied pid --> pass
            except:
                pass

        # pid가 새로 생긴건 갱신
        else:
            Form.ProcessInfo.createProcess(newPid)
            befPcList[newPid] = newPcList[newPid]
            try:
                Form.OperInject.setFirstAppDllHash(newPid)
                print(Form.OperInject.initDllHashTable)
            except Exception as e:
                print("new --> {}".format(e))
    # 죽은 프로세스는 삭제
    for befPid in befPcList:
        if befPid not in newPcList:
            delPidList.append(befPid)
    for i in delPidList:
        del befPcList[i]
        Form.OperInject.delDllInfo(i)
        print(Form.OperInject.initDllHashTable)
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