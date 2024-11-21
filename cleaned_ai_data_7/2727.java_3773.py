import abc

class AutoConfigStateField(metaclass=abc.ABCMeta):
    def __init__(self):
        raise AssertionError()

    @property
    def codec(self) -> type:
        return DefaultConfigFieldCodec

@AutoConfigStateField.register
class DefaultConfigFieldCodec(ABC):
    pass
