from enum import Enum

class VTIndices(Enum):
    RESET = 0
    GET_NEXT = 1


class IKeyEnumerator:
    IID_IKEY_ENUMERATOR = "345FA92E-5E00-4319-9CAE-971F7601CDCF"

    def __init__(self):
        pass

    def Reset(self) -> int:
        # Implement the logic for Reset method
        return 0

    def GetNext(self, key: str, value: object, metadata: object) -> int:
        # Implement the logic for GetNext method
        return 0


if __name__ == "__main__":
    ike = IKeyEnumerator()
    print(ike.Reset())
    print(ike.GetNext("key", None, None))
