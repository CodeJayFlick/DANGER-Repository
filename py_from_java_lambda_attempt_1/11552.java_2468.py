Here is the translation of the Java code into Python:

```Python
class NamespaceUtils:
    def __init__(self):
        pass  # singleton utils class--no public construction

    @staticmethod
    def get_namespace_path_without_library(namespace: 'Namespace') -> str:
        result = ''
        while namespace and not isinstance(namespace, GlobalNamespace) and not isinstance(namespace, Library):
            result += namespace.name + '::' if result else namespace.name
            namespace = namespace.parent_namespace
        return result

    @staticmethod
    def get_namespace_qualified_name(namespace: 'Namespace', symbol_name: str, exclude_library_name: bool) -> str:
        result = ''
        if not exclude_library_name and isinstance(namespace, Library):
            result += get_namespace_path_without_library(namespace)
        elif namespace is not None and not isinstance(namespace, GlobalNamespace):
            result += namespace.name + '::' if result else namespace.name
        return f'{result}{symbol_name}'

    @staticmethod
    def get_library(namespace: 'Namespace') -> 'Library':
        ns = namespace
        while isinstance(ns, Library) or isinstance(ns, Namespace):
            if isinstance(ns, Library):
                return ns
            ns = ns.parent_namespace
        return None

    @staticmethod
    def get_namespaces_by_name(program: 'Program', parent: 'Namespace', name: str) -> list:
        validate(program, parent)
        symbols = program.symbol_table.get_symbols(name, parent)
        namespaces = []
        for symbol in symbols:
            if isinstance(symbol.object(), Namespace):
                namespaces.append(symbol.object())
        return namespaces

    @staticmethod
    def get_namespace_by_path(program: 'Program', parent: 'Namespace', path_string: str) -> list:
        validate(program, parent)
        parent = adjust_for_null_root_namespace(parent, path_string, program)
        if not path_string:
            return [parent]
        namespace_names = SymbolPath(path_string).as_list()
        namespaces = doGet_namespaces(namespace_names, parent, program)
        return namespaces

    @staticmethod
    def get_matching_namespaces(child_name: str, parents: list, program: 'Program') -> list:
        validate(program, parents)
        result = []
        for namespace in parents:
            result.extend(get_namespaces_by_name(program, namespace, child_name))
        return result

    @staticmethod
    def search_for_all_symbols_in_any_of_these_namespaces(parents: list, symbol_name: str, program: 'Program') -> list:
        result = []
        for parent in parents:
            result.extend(program.symbol_table.get_symbols(symbol_name, parent))
        return result

    @staticmethod
    def get_symbols(symbol_path: str, program: 'Program') -> list:
        namespace_names = SymbolPath(symbol_path).as_list()
        if not namespace_names:
            return []
        symbol_name = namespace_names.pop()
        parents = doGet_namespaces(namespace_names, None, program)
        return search_for_all_symbols_in_any_of_these_namespaces(parents, symbol_name, program)

    @staticmethod
    def get_first_non_function_namespace(parent: 'Namespace', name: str, program: 'Program') -> 'Namespace':
        validate(program, parent)
        symbols = program.symbol_table.get_symbols(name, parent)
        for symbol in symbols:
            if isinstance(symbol.object(), Namespace) and not isinstance(symbol.object().get_symbol_type(), SymbolType.FUNCTION):
                return symbol.object()
        return None

    @staticmethod
    def create_namespace_hierarchy(namespace_path: str, root_namespace: 'Namespace', program: 'Program', address: Address = None, source: int = 0) -> 'Namespace':
        validate(program, root_namespace)
        if not namespace_path:
            return root_namespace
        symbol_path = SymbolPath(namespace_path)
        namespace_names = symbol_path.as_list()
        parent = root_namespace
        for name in namespace_names:
            parent = get_namespace(program, parent, name, address) or program.symbol_table.create_name_space(parent, name, source)
        return parent

    @staticmethod
    def get_function_namespace_at(program: 'Program', symbol_path: str, address: Address) -> 'Namespace':
        if not symbol_path or not address:
            return None
        symbols = program.symbol_table.get_symbols_as_iterator(address)
        for symbol in symbols:
            if isinstance(symbol.object(), Function):
                if symbol_path.matches_path_of(symbol):
                    return symbol.object()
        return None

    @staticmethod
    def get_function_namespace_containing(program: 'Program', symbol_path: str, address: Address) -> 'Namespace':
        if not symbol_path or not address:
            return None
        function_manager = program.function_manager
        function = function_manager.get_function-containing(address)
        if function and symbol_path.matches_path_of(function.symbol):
            return function
        return None

    @staticmethod
    def get_non_function_namespace(program: 'Program', symbol_path: str) -> 'Namespace':
        if not symbol_path:
            return program.global_namespace
        symbols = program.symbol_table.get_symbols(symbol_path, None)
        for symbol in symbols:
            if isinstance(symbol.object(), Namespace):
                return symbol.object()
        return None

    @staticmethod
    def convert_namespace_to_class(namespace: 'Namespace') -> 'GhidraClass':
        # todo implement this method
        pass  # singleton utils class--no public construction

    @staticmethod
    def get_namespace_parts(namespace: 'Namespace') -> list:
        result = []
        while not namespace.is_global():
            result.insert(0, namespace)
            namespace = namespace.parent_namespace
        return result


def validate(program: 'Program', parent: 'Namespace'):
    if parent and not isinstance(parent, GlobalNamespace):
        if program != parent.symbol.get_program():
            raise ValueError("Given namespace does not belong to the given program")


def adjust_for_null_root_namespace(parent: 'Namespace', path_string: str, program: 'Program') -> 'Namespace':
    global_namespace = program.global_namespace
    if path_string and path_string.startswith(global_namespace.name):
        return global_namespace
    elif parent:
        return parent
    else:
        return global_namespace


def get_namespace(program: 'Program', namespace: 'Namespace', name: str, address: Address) -> 'Namespace':
    # todo implement this method
    pass  # singleton utils class--no public construction

# Usage example:

program = Program()  # Create a new program instance.
namespace_utils = NamespaceUtils()

namespace_path_without_library = namespace_utils.get_namespace_path_without_library(program.global_namespace)
print(namespace_path_without_library)

symbol_name = "my_symbol"
exclude_library_name = True
namespace_qualified_name = namespace_utils.get_namespace_qualified_name(program.global_namespace, symbol_name, exclude_library_name)
print(namespace_qualified_name)

library = program.symbol_table.create_library("My Library")
get_namespaces_by_name_result = namespace_utils.get_namespaces_by_name(program, library, "my_symbol")
for namespace in get_namespaces_by_name_result:
    print(namespace.name)

namespace_path_string = "ns1::ns2::ns3"
parent_namespace = None
namespaces = namespace_utils.get_namespace_by_path(program, parent_namespace, namespace_path_string)
for namespace in namespaces:
    print(namespace.name)

child_name = "my_child_symbol"
parents = [program.global_namespace]
matching_namespaces = namespace_utils.get_matching_namespaces(child_name, parents, program)
for namespace in matching_namespaces:
    print(namespace.name)

symbol_path = "ns1::ns2::my_function"
address = Address(0x10000000)  # Create a new address instance.
function_namespace_at_result = namespace_utils.get_function_namespace_at(program, symbol_path, address)
print(function_namespace_at_result.name if function_namespace_at_result else None)

function_namespace_containing_result = namespace_utils.get_function_namespace_containing(program, symbol_path, address)
print(function_namespace_containing_result.name if function_namespace_containing_result else None)

non_function_namespace = program.symbol_table.create_name_space(None, "my_non_function_symbol", 0)  # Create a new non-function namespace.
get_non_function_namespace_result = namespace_utils.get_non_function_namespace(program, symbol_path)
print(get_non_function_namespace_result.name if get_non_function_namespace_result else None)

namespace_parts = namespace_utils.get_namespace_parts(non_function_namespace)
for part in namespace_parts:
    print(part.name)