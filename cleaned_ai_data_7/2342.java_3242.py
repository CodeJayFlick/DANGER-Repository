import abc
from typing import Any, Dict, List, Tuple

class DBTraceRegisterContextManager:
    NAME = "RegisterContext"

    class DBTraceRegisterContextEntry(abc.ABC):
        VALUE_COLUMN_NAME = "Value"
        value: bytes

        def __init__(self, tree, store, record):
            super().__init__()
            self.value = None
            update(self)

        @staticmethod
        def get_value() -> bytes:
            return None

    language_manager: Any
    default_contexts: Dict[Language, ProgramContext]

    def __init__(self, dbh, open_mode, lock, monitor, base_language, trace,
                 thread_manager, language_manager):
        super().__init__()
        self.language_manager = language_manager
        self.default_contexts = {}

        load_spaces()

    @abc.abstractmethod
    def create_space(self, space: Any, ent: Any) -> DBTraceRegisterContextSpace:
        pass

    @abc.abstractmethod
    def create_register_space(self, space: Any, thread: Any, ent: Any) -> DBTraceRegisterContextRegisterSpace:
        pass

    def get_for_space(self, space: Any, create_if_absent: bool = False):
        return super().get_for_space(space, create_if_absent)

    @abc.abstractmethod
    def read_lock(self) -> Lock:
        pass

    @abc.abstractmethod
    def write_lock(self) -> Lock:
        pass

    def get_register_context_space(self, space: Any, create_if_absent: bool = False):
        return self.get_for_space(space, create_if_absent)

    def get_register_context_register_space(self, thread: Any, create_if_absent: bool = False):
        return self.get_for_register_space(thread, 0, create_if_absent)

    @abc.abstractmethod
    def generate_default_context(self, language: Language) -> ProgramContext:
        pass

    def default_context(self, language: Language) -> ProgramContext:
        if not self.default_contexts.get(language):
            return self.generate_default_context(language)
        else:
            return self.default_contexts[language]

    @abc.abstractmethod
    def get_default_value(self, language: Any, register: Any, address: Address) -> RegisterValue:
        pass

    @abc.abstractmethod
    def set_value(self, language: Language, value: RegisterValue, lifespan: Range,
                  range: AddressRange):
        pass

    @abc.abstractmethod
    def remove_value(self, language: Language, register: Any, span: Range, range: AddressRange):
        pass

    @abc.abstractmethod
    def get_value(self, language: Language, register: Any, snap: long,
                  address: Address) -> RegisterValue:
        pass

    @abc.abstractmethod
    def get_entry(self, language: Language, register: Any, snap: long, address: Address):
        pass

    @abc.abstractmethod
    def get_value_with_default(self, language: Language, register: Any, snap: long,
                                address: Address) -> RegisterValue:
        pass

    @abc.abstractmethod
    def get_register_value_address_ranges(self, language: Language, register: Any, snap: long,
                                           within: AddressRange):
        pass

    @abc.abstractmethod
    def has_register_value_in_address_range(self, language: Language, register: Any, snap: long,
                                              within: AddressRange) -> bool:
        pass

    @abc.abstractmethod
    def has_register_value(self, language: Language, register: Any, snap: long):
        pass

    @abc.abstractmethod
    def clear(self, span: Range, range: AddressRange):
        pass


class ProgramContext(abc.ABC):
    def get_default_value(self, register: Any, address: Address) -> RegisterValue:
        pass

    def apply_context_settings(self, context: Any):
        pass


class Language:
    @abc.abstractmethod
    def apply_context_settings(self, context: Any):
        pass


class DBTraceRegisterContextSpace(abc.ABC):
    pass


class DBTraceRegisterContextRegisterSpace(abc.ABC):
    pass

