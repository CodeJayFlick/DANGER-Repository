class FunctionNameStringable:
    SHORT_NAME = "FUN_SYM"

    def __init__(self):
        self.symbol_name = None
        self.source_type = None
        self.namespace_infos = []

    def apply_function_name(self, program: object, function: object) -> None:
        if not isinstance(program, Program):
            raise TypeError("Program must be an instance of 'Program'")

        entry_point = function.get_entry_point()
        if entry_point.is_memory_address() and self.source_type == SourceType.DEFAULT:
            # Apply a default name by removing the current one.
            program.symbol_table.remove_symbol_special(function.get_symbol())
            return

        symbol_table = program.symbol_table
        namespace = program.global_namespace
        for info in self.namespace_infos:
            ns = symbol_table.get_namespace(info.name, namespace)
            if ns is not None:
                if function.is_external() != ns.is_external():
                    raise DuplicateNameException("Conflicting namespace: " + info.name)

                if info.symbol_type == SymbolType.CLASS and \
                   ns.get_symbol().get_symbol_type() == SymbolType.NAMESPACE:
                    # Promote existing namespace to class
                    ns = NamespaceUtils.convert_namespace_to_class(ns)
                namespace = ns

            else:
                namespace = self.create_namespace(program, info, namespace)

        symbol = function.get_symbol()
        symbol.set_name_and_namespace(self.symbol_name, namespace, self.source_type)

    def add_function_name(self, program: object, function: object, is_primary: bool) -> None:
        if not isinstance(program, Program):
            raise TypeError("Program must be an instance of 'Program'")

        symbol_table = program.symbol_table
        namespace = program.global_namespace

        for info in self.namespace_infos:
            ns = symbol_table.get_namespace(info.name, namespace)
            namespace = ns if ns is not None else self.create_namespace(program, info, namespace)

        function_symbol = function.get_symbol()
        if function_symbol.source_type == SourceType.DEFAULT:
            function_symbol.set_name_and_namespace(self.symbol_name, namespace, self.source_type)
        else:
            # Add a label.
            added_symbol = symbol_table.create_label(function.entry_point(), self.symbol_name,
                                                       namespace, self.source_type)

            if is_primary and added_symbol is not None:
                set_label_primary_cmd = SetLabelPrimaryCmd(added_symbol.address, added_symbol.name,
                                                            added_symbol.parent_namespace)
                set_label_primary_cmd.apply_to(program)

    def create_namespace(self, program: object, info: NamespaceInfo, namespace: object) -> object:
        if isinstance(info.symbol_type, SymbolType):
            return symbol_table.create_external_library(info.name, info.source_type)
        elif isinstance(info.symbol_type, SymbolType.CLASS):
            return symbol_table.create_class(namespace, info.name, info.source_type)
        else:
            return symbol_table.create_namespace(namespace, info.name, info.source_type)

    def __hash__(self) -> int:
        prime = 31
        result = 1

        if self.source_type is not None:
            result *= prime + hash(self.source_type)
        if self.symbol_name is not None:
            result *= prime + hash(self.symbol_name)

        return result

    def __eq__(self, other: object) -> bool:
        if self == other:
            return True
        elif isinstance(other, FunctionNameStringable):
            if self.symbol_name != other.symbol_name or \
               self.source_type != other.source_type or \
               len(self.namespace_infos) != len(other.namespace_infos):
                return False

            for i in range(len(self.namespace_infos)):
                if not (self.namespace_infos[i].name == other.namespace_infos[i].name and
                        self.namespace_infos[i].symbol_type == other.namespace_infos[i].symbol_type and
                        self.namespace_infos[i].source_type == other.namespace_infos[i].source_type):
                    return False

            return True
        else:
            return NotImplemented


class NamespaceInfo:
    def __init__(self, namespace: object) -> None:
        if isinstance(namespace, Namespace):
            self.name = namespace.get_name()
            self.symbol_type = namespace.get_symbol().get_symbol_type()
            self.source_type = namespace.get_symbol().get_source()

    def __eq__(self, other: object) -> bool:
        if not (isinstance(other, NamespaceInfo)):
            return NotImplemented

        return self.name == other.name and \
               self.symbol_type == other.symbol_type and \
               self.source_type == other.source_type


class SetLabelPrimaryCmd:
    def apply_to(self, program: object):
        pass
