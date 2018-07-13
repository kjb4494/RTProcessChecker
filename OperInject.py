import os
import hashlib
import ProcessInfo
import psutil


class OperInject:
    def __init__(self):
        # system 폴더의 모든 DLL 데이터 해쉬를 저장한다.
        # key: 파일명, value: 해쉬값
        self.sys32HashTable = {}
        # 최초 응용프로그램의 DLL 데이터 해쉬를 저장한다.
        # key: pid, value: {key: 파일명, value: 해쉬값}
        self.initDllHashTable = {}
        print("System DLL File Hash Table 생성중...")
        for path in ['C:\Windows\System32', 'C:\Windows\SysWOW64']:
            for root, dirs, files in os.walk(path):
                for fname in files:
                    fPath = os.path.join(root, fname)
                    if fPath[-3:].lower() == 'dll':
                        try:
                            fHash = self.operFileHash(fPath)
                        except:
                            continue
                        self.sys32HashTable[fPath] = fHash
        print("생성 완료!")

    # 파일의 해시를 계산
    def operFileHash(self, fPath):
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

    # DLL 정보가 등록되어 있나?
    def isExistAppDllHash(self, pid):
        if pid in self.initDllHashTable:
            return True
        return False

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
                    if dll.path in self.operFileHash:
                        if self.sys32HashTable[dll.path] == self.operFileHash(dll.path):
                            print("정상 시스템 파일임")
                            continue
                        else:
                            print("인젝션된 파일임!")
                            return 100
                    else:
                        if dll.path in self.initDllHashTable[pid]:
                            if self.initDllHashTable[pid][dll.path] == self.operFileHash(dll.path):
                                print("정상 DLL 파일임")
                            else:
                                print("인젝션된 파일임!")
                                return 100
                        else:
                            print("인젝션 가능성이 있음")
                            return 50
            except:
                continue
        return 0


def test():
    dicA = {'123': {'asdf': 'ghjk',
                    'zxcv': 'bnm',
                    'qwer': 'tyui',
                    'uiop': 'aaaa'},
            '124': {'asdf': 'ghjk'},
            '125': {'asdf': 'ghjk'},
            '126': {'asdf': 'ghjk'}}

    if 'zxcv' in dicA['123']:
        print(dicA['123']['zxcv'])


if __name__ == "__main__":
    test()
