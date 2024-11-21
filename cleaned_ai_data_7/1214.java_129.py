from enum import Enum

class VTIndices(Enum):
    RESET = 0
    GET_NEXT = 1


class IUnknownEx:
    pass


class IRawEnumerator(IUnknownEx):
    IID_IRAW_ENUMERATOR = "E13613F9-3A3C-40b5-8F48-1E5EBFB9B21B"

    def Reset(self) -> int:
        # implement the method
        return 0

    def GetNext(self, name: str, kind: int, value: object) -> int:
        # implement the method
        return 0


# Example usage:

class RawEnumerator(IRawEnumerator):
    pass


def main():
    enumerator = RawEnumerator()
    result1 = enumerator.Reset()  # call Reset method
    result2 = enumerator.GetNext("name", 123, "value")  # call GetNext method

if __name__ == "__main__":
    main()

