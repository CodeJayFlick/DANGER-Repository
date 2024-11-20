class VTMatchTag:
    UNTAGGED = object()

    def __init__(self):
        pass

    def get_name(self) -> str:
        return ""

    def __str__(self) -> str:
        return "<Not Tagged>"

    def compare_to(self, other: 'VTMatchTag') -> int:
        if not isinstance(other, VTMatchTag):
            raise TypeError("Only VTMatchTag objects can be compared")
        return self.get_name().lower() > other.get_name().lower()

class Comparable(metaclass=abc.ABCMeta):

    @abstractmethod
    def compare_to(self, other: 'Comparable') -> int:
        pass

if __name__ == "__main__":
    print(VTMatchTag.UNTAGGED)
