Here is the translation of the given Java code into Python:

```Python
class Changer:
    class ChangeMode(enum.Enum):
        ADD = 1
        SET = 2
        REMOVE = 3
        REMOVE_ALL = 4
        DELETE = 5
        RESET = 6

    def __init__(self):
        pass

    @classmethod
    def accept_change(cls, mode: 'ChangeMode') -> typing.List[typing.Type]:
        if mode == Changer.ChangeMode.ADD:
            return [int]
        elif mode in (Changer.ChangeMode.SET, Changer.ChangeMode.REMOVE_ALL):
            return [str]
        else:
            return []

    @classmethod
    def change(cls, what: list, delta: typing.List[object], mode: 'ChangeMode'):
        if mode == Changer.ChangeMode.ADD:
            for item in delta:
                what.append(item)
        elif mode == Changer.ChangeMode.SET:
            what = delta
        elif mode == Changer.ChangeMode.REMOVE_ALL:
            what.clear()
        else:
            raise ValueError("Unsupported Change Mode")

class Expression:
    def __init__(self):
        pass

def changer_utils(changer: 'Changer', what, delta, mode) -> None:
    if isinstance(what[0], list):
        for item in what:
            changer.change(item, delta, mode)
    else:
        changer.change(what, delta, mode)

def accepts_change(e: Expression, mode: Changer.ChangeMode, types: typing.List[type]) -> bool:
    cs = e.accept_change(mode)
    if not cs:
        return False
    for type in types:
        for c in cs:
            if isinstance(c, list) and issubclass(type, c[0]):
                return True
            elif issubclass(type, c):
                return True
    return False

```

Please note that Python does not have a direct equivalent to Java's `@Nullable` annotation.