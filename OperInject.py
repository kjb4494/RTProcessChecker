import os
import hashlib
import ProcessInfo
import psutil


class OperInject:
    def __init__(self):
        # system32의 모든 DLL 데이터 해쉬를 저장한다.
        # key: 파일명, value: 해쉬값
        self.sys32HashTable = {}
        print("System32 Hash Table 생성중...")
        for root, dirs, files in os.walk('C:\Windows\System32'):
            for fname in files:
                fPath = os.path.join(root, fname)
                fLowerPath = fPath.lower()
                if fLowerPath[-3:] in ['dll', 'nls', 'mui', 'cpl']:
                    try:
                        fHash = self.operFileHash(fPath)
                    except:
                        continue
                    self.sys32HashTable[fPath] = fHash

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

    # ProcessInfo 객체의 PID 가져와서 검사
    def InjectCheck(self, ProcessInfo):
        for pid in ProcessInfo.dic_processList:
            p = psutil.Process(pid)
            for dll in p.memory_maps():
                # 시스템 파일일 경우
                # 시스템 해시 테이블에 존재하지않으면 except로 넘어간다.
                try:
                    if self.sys32HashTable[dll.path] == self.operFileHash(dll.path):
                        print("시스템 파일임")
                    else:
                        print("인젝션된 파일임")
                # 응용프로그램 DLL파일일 경우
                except:
                    print("응용프로그램 DLL 파일임")


def test():
    obOperInject = OperInject()


if __name__ == "__main__":
    test()
