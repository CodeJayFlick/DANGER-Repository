from enum import Enum

class VTableIndex(Enum):
    LINEARIZE_LOCATION = 0


class LOCATION:
    pass


def linearize_location(context: int, location: 'LOCATION', p_linearized_location: 'LOCATION') -> None:
    # Your implementation here
    pass


class IDebugHostMemory2:
    IID_IDEBUG_HOST_MEMORY2 = "EEA033DE-38F6-416b-A251-1D3771001270"

    class VTIndices2(VTableIndex):
        start = VTableIndex.LINEARIZE_LOCATION

        def get_index(self) -> int:
            return self.value + self.start


def main():
    # Your implementation here
    pass


if __name__ == "__main__":
    main()
