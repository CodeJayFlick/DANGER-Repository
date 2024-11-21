import enum
from typing import Any, List

class VTableIndex(enum.IntEnum):
    def __init__(self) -> None:
        pass

    @classmethod
    def follow(cls: type['VTableIndex'], prev: 'VTableIndex') -> int:
        all = list(prev.__subclasses__())
        start = all[0].value - all[0].__members__.keys()[0]
        return len(all) + start


class UnknownWithUtils:
    def __init__(self, pv_instance=None):
        pass

    @property
    def vtable_index(self) -> VTableIndex:
        raise NotImplementedError("VTable Index not implemented")

    def invoke_hr(self, idx: int, *args: Any) -> int:
        # if idx != IDebugClient.VTIndices.DISPATCH_CALLBACKS and \
        #     idx != IDebugControl.VTIndices.GET_EXECUTION_STATUS:
        print(f"Invoked {idx} with arguments {args}")
        return 0


# Example usage
class VTableIndexEnum(VTableIndex):
    INDEX1 = enum.auto()
    INDEX2 = enum.auto()

vtable_index_enum = VTableIndexEnum.INDEX1

unknown_with_utils = UnknownWithUtils(pv_instance=None)
result = unknown_with_utils.invoke_hr(vtable_index_enum, "Hello", 12345)

print(f"Result: {result}")
