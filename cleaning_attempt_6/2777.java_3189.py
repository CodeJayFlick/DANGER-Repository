class SleighUseropLibrary:
    class EmptySleighUseropLibrary(SleighUseropLibrary):
        def get_userops(self) -> dict:
            return {}

    NIL = EmptySleighUseropLibrary()

    @staticmethod
    def nil() -> 'SleighUseropLibrary[object]':
        return NIL

    class SleighUseropDefinition(metaclass=abc.ABCMeta):
        @abstractmethod
        def get_name(self) -> str:
            pass

        @abstractmethod
        def get_operand_count(self) -> int:
            pass

        @abstractmethod
        def execute(self, state: 'PcodeExecutorStatePiece[object]', out_var: Varnode, in_vars: list[Varnode]) -> None:
            pass

    userops = {}

    def __init__(self):
        self.userops = {}

    def get_userops(self) -> dict:
        return self.userops

    def compose(self, lib: 'SleighUseropLibrary[object]') -> 'SleighUseropLibrary[object]':
        if lib is None:
            return self
        return ComposedSleighUseropLibrary([self, lib])

    def get_symbols(self, language: SleighLanguage) -> dict[int, UserOpSymbol]:
        symbols = {}
        all_names = set()
        lang_op_count = len(language.get_user_defined_ops())
        for i in range(lang_op_count):
            name = language.get_user_defined_op_name(i)
            all_names.add(name)

        next_op_no = lang_op_count
        for uop in self.userops.values():
            op_name = uop.get_name()
            if not all_names.add(op_name):
                continue

            op_no = next_op_no
            symbols[op_no] = UserOpSymbol(Location(f"{self.__class__.__name__}:{op_name}", 0), op_name)
            symbols[op_no].set_index(op_no)

        return symbols


from abc import ABC, abstractmethod
