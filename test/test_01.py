# 코드 테스트를 위한 공간입니다.

import OperVt
import pprint


def test():
    obOperVt = OperVt.OperVt()
    obOperVt.setApiKey("15b841c3fa1ea901a71c36690fb1a8f8602c197035089fd3721eb70542e6ff18")
    obOperVt.rpAnalysis("7657fcb7d772448a6d8504e4b20168b8")
    pprint.pprint(obOperVt.getRpResult())
    print(obOperVt.getPercentage())


if __name__ == "__main__":
    test()
