import os
import hashlib
import psutil


class OperInject:
    def __init__(self):
        self.ExceptedFile = ['C:\\Windows\\System32\\wow64.dll',
                             'C:\\Windows\\System32\\wow64cpu.dll',
                             'C:\\Windows\\System32\\wow64win.dll',
                             'C:\\Windows\\System32\\UIRibbonRes.dll',
                             'C:\\Windows\\System32\\RltkAPO64.dll']

        # system 폴더의 모든 DLL 데이터 해쉬를 저장한다.
        # key: 파일명, value: 해쉬값
        self.sys32HashTable = {}
        # 최초 응용프로그램의 DLL 데이터 해쉬를 저장한다.
        # key: pid, value: {key: 파일명, value: 해쉬값}
        self.initDllHashTable = {}

        for fPath in self.ExceptedFile:
            self.sys32HashTable[fPath] = ""

        print("System DLL File Hash Table 생성중...")
        for path in ['C:\Windows\System32', 'C:\Windows\SysWOW64']:
            for root, dirs, files in os.walk(path):
                for fname in files:
                    fPath = os.path.join(root, fname)
                    if fPath[-3:].lower() == 'dll':
                        try:
                            fHash = self.operFileHash(fPath)
                        except:
                            self.ExceptedFile.append(fPath)
                            fHash = ""
                        self.sys32HashTable[fPath] = fHash
        print("생성 완료!")

    # 파일의 해시를 계산
    def operFileHash(self, fPath):
        if fPath in self.ExceptedFile:
            return ''
        blocksize = 65536
        afile = open(fPath, 'rb')
        hasher = hashlib.md5()
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(blocksize)
        afile.close()
        return hasher.hexdigest()

    # pid의 최초 DLL 데이터 해쉬 설정
    def setFirstAppDllHash(self, pid):
        fileDic = {}
        p = psutil.Process(pid)
        for dll in p.memory_maps():
            try:
                if dll.path[-3:].lower() == 'dll':
                    if dll.path not in self.sys32HashTable:
                        fHash = self.operFileHash(dll.path)
                        fileDic[dll.path] = fHash
            except:
                continue
        self.initDllHashTable[pid] = fileDic


    # PID가 죽으면 정보도 같이 소멸
    def delDllInfo(self, pid):
        if pid in self.initDllHashTable:
            del self.initDllHashTable[pid]

    # PID의 DLL 인젝션 여부
    # 100: 인젝션 파일, 50: 의심, 0: 정상
    def isInjected(self, pid):
        p = psutil.Process(pid)
        for dll in p.memory_maps():
            try:
                if dll.path[-3:].lower() == 'dll':
                    # 시스템 파일일 경우
                    # 시스템 해시 테이블에 존재하지않으면 except로 넘어간다.
                    if dll.path in self.sys32HashTable:
                        # 정상 시스템 파일
                        if self.sys32HashTable[dll.path] == self.operFileHash(dll.path):
                            continue
                        # 인젝션된 시스템 파일
                        else:
                            return "INJECTED!"
                    # 응용프로그램의 DLL 파일일 경우
                    else:
                        if dll.path in self.initDllHashTable[pid]:
                            # 정상 DLL
                            if self.initDllHashTable[pid][dll.path] == self.operFileHash(dll.path):
                                continue
                            # 인젝션 DLL
                            else:
                                return "INJECTED!"
                        # 초기값과 다른 의심 파일이 있음
                        else:
                            print("{}: {}".format(pid, dll.path))
                            return "INJECTION DETECTED!"
            except:
                continue
        return "OK"
