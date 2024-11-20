import sys
from abc import ABCMeta, abstractmethod


class DbgEngUtil(metaclass=ABCMeta):
    DEBUG_ANY_ID = -1

    def __init__(self):
        pass  # private constructor

    @abstractmethod
    class InterfaceSupplier:
        def get(self, refiid: int, p_client) -> tuple[int, object]:
            ...

    def try_preferred_interfaces(cls: type[I], preferred: dict[REFIID, type[I]], supplier: InterfaceSupplier) -> I | None:
        pp_client = PointerByReference()
        for ent in preferred.values():
            try:
                if not supplier.get(ent.INTERFACE_ID, pp_client):
                    continue
                impl = cls.__new__(cls)
                instance_for_method = getattr(cls, "instanceFor")
                instance = instance_for_method(impl)
                return instance  # type: ignore
            except Exception as e:
                print(f"Error {e}")
        raise DbgEngRuntimeException("None of the preferred interfaces are supported")

    def lazy_weak_cache(cache: dict[Pointer, object], unk: Unknown, for_new: callable[[Unknown], object]) -> object | None:
        present = cache.get(unk.pointer)
        if present is not None:
            unk.release()
            return present
        absent = for_new(unk)
        cache[unk.pointer] = absent
        return absent

    def dbgline():
        print(sys.exc_info()[1])
        sys.stdout.flush()

class DbgEngRuntimeException(Exception):
    pass


class Unknown(metaclass=ABCMeta):
    @abstractmethod
    def get_pointer(self) -> Pointer:
        ...

    def release(self):
        ...
