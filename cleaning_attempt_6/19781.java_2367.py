from abc import ABCMeta, abstractmethod
import itertools

class Expression(metaclass=ABCMeta):
    @abstractmethod
    def get_single(self, e: 'Event') -> T:
        pass

    @abstractmethod
    def get_array(self, e: 'Event') -> list[T]:
        pass

    @abstractmethod
    def get_all(self, e: 'Event') -> list[T]:
        pass

    @abstractmethod
    def is_single(self) -> bool:
        pass

    @abstractmethod
    def check(self, e: 'Event', c: 'Checker[super T]', negated: bool) -> bool:
        pass

    @abstractmethod
    def get_converted_expression(self, to: list[type[R]]) -> Expression[R]:
        pass

    @abstractmethod
    def get_return_type(self) -> type[T]:
        pass

    @abstractmethod
    def get_and(self) -> bool:
        pass

    @abstractmethod
    def set_time(self, time: int) -> None:
        pass

    @property
    @abstractmethod
    def time(self) -> int:
        pass

    @abstractmethod
    def is_default(self) -> bool:
        pass

    @abstractmethod
    def iterator(self, e: 'Event') -> itertools.Iterator[T]:
        pass

    @abstractmethod
    def is_loop_of(self, s: str) -> bool:
        pass

    @property
    @abstractmethod
    def source(self) -> Expression[super T]:
        pass

    @abstractmethod
    def simplify(self) -> Expression[super T]:
        pass

    @abstractmethod
    def accept_change(self, mode: 'ChangeMode') -> list[type[R]]:
        pass

    @abstractmethod
    def change(self, e: 'Event', delta: list[object], mode: 'ChangeMode') -> None:
        pass

    def before_change(self, changed: 'Expression[super T]', delta: list[object]) -> list[object]:
        if not delta or len(delta) == 0:
            return []

        new_delta = []
        for value in delta:
            if isinstance(value, Slot):
                item_stack = value.get_item()
                if item_stack is not None:
                    item_stack = item_stack.clone()  # ItemStack in inventory is mutable
                else:
                    continue

                new_delta.append(item_stack)
            elif hasattr(Classes, 'clone'):
                new_delta.append(Classes.clone(value))
        return new_delta or delta
