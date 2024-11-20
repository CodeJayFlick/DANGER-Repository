Here is the translation of the Java code into Python:

```Python
class ExternalLocationDB:
    def __init__(self, ext_mgr, symbol):
        self.ext_mgr = ext_mgr
        self.symbol = symbol

    def get_symbol(self):
        return self.symbol

    def get_library_name(self):
        library = self.get_library()
        if library is not None:
            return library.name
        else:
            return "<UNKNOWN>"

    def get_library(self):
        parent_namespace = self.symbol.parent_namespace
        while parent_namespace is not None and not isinstance(parent_namespace, Library):
            parent_namespace = parent_namespace.parent_namespace
        return parent_namespace

    def get_parent_name_space(self):
        return self.symbol.parent_namespace

    def get_parent_name(self):
        return self.get_parent_name_space().name if self.get_parent_name_space() else ""

    def get_ext_name_id(self):
        return self.symbol.parent_namespace.id

    def get_label(self):
        return self.symbol.name

    def get_original_imported_name(self):
        return self.get_external_data(self.symbol).get_original_imported_name()

    def get_source(self):
        return self.symbol.source

    def get_address(self):
        if self.symbol.address is not None:
            return self.symbol.address
        else:
            return ""

    def get_external_space_address(self):
        return self.symbol.address

    def __str__(self):
        builder = f"{self.get_label()}"
        if self.get_original_imported_name():
            builder += f" ({self.get_original_imported_name()})"
        return builder

    def is_function(self):
        return self.symbol.symbol_type == "FUNCTION"

    def get_data_type(self):
        data_type_id = self.symbol.data_type_id
        if data_type_id < 0:
            return None
        else:
            return self.ext_mgr.get_program().get_data_type_manager().get_data_type(data_type_id)

    def set_data_type(self, dt):
        data_type_id = self.ext_mgr.get_program().get_data_type_manager().get_resolved_id(dt)
        self.symbol.set_data_type_id(data_type_id)

    def get_function(self):
        if self.symbol.symbol_type == "FUNCTION":
            return self.symbol.object
        else:
            return None

    def create_function(self):
        if self.symbol.symbol_type == "FUNCTION":
            return self.get_function()
        else:
            function = self.ext_mgr.create_function(self)
            self.symbol = symboldb(function.get_symbol())
            return function

    def set_label(self, label, source):
        if label is None or len(label) == 0:
            if source != SourceType.DEFAULT and isinstance(self.symbol.parent_namespace, Library):
                self.set_name(None, None, source)
            else:
                raise InvalidInputException("Either an external label or address is required")
        elif not isinstance(self.symbol.parent_namespace, Library):
            namespace = NamespaceUtils.create_namespace_hierarchy(label.split(Namespace.DELIMITER)[0], self.ext_mgr.get_program(), source)
            self.set_name(namespace, None if len(label) == 1 else label[1:], source)

    def set_address(self, address):
        if address is not None and not isinstance(address, Address):
            raise InvalidInputException("Invalid memory address")
        elif address is None:
            return
        self.label = address

    def save_original_name_if_needed(self, old_namespace, old_name, old_source):
        was_in_library = isinstance(old_namespace, Library)
        original_imported_name = self.get_original_imported_name()
        if label == original_imported_name and source != SourceType.DEFAULT:
            set_original_imported_name(symboldb(None), None)
        elif was_in_library and source != SourceType.DEFAULT and old_source == SourceType.IMPORTED and original_imported_name is None:
            set_original_imported_name(symboldb(old_namespace), old_name)

    def restore_original_name(self):
        if self.get_original_imported_name() is not None or other.get_original_imported_name() is not None:
            return
        try:
            library = NamespaceUtils.get_library(self.symbol.parent_namespace)
            self.set_name(library, None, SourceType.IMPORTED)
            set_original_imported_name(symboldb(None), None)
        except (CircularDependencyException, DuplicateNameException, InvalidInputException):
            raise AssertException("Can't happen here", e)

    def __eq__(self, other):
        if not isinstance(other, ExternalLocationDB):
            return False
        return self.symbol == other.symbol

    def is_equivalent(self, other):
        if not isinstance(other, ExternalLocation):
            return False
        if self.is_function() != other.is_function():
            return False
        name = self.get_label()
        original_import_name = self.get_original_imported_name()
        other_name = other.get_label()
        other_original_import_name = other.get_original_imported_name()

        if original_import_name is not None and original_import_name == other_original_import_name:
            return True

        if other_name == original_import_name:
            return True
        if name == other_original_import_name:
            return True

        if self.symbol.name(1) == other.symbol.name(1):
            return SystemUtilities.is_equal(self.get_address(), other.get_address())

    @staticmethod
    def get_external_data(ext_symbol):
        return ExternalData(ext_symbol.symbol_string_data)

    @staticmethod
    def set_original_imported_name(ext_symbol, name):
        update_symbol_data(ext_symbol, name, get_external_data(ext_symbol).get_address_string())

    @staticmethod
    def update_symbol_data(ext_symbol, original_imported_name, address_string):
        if address_string is None and original_imported_name is None:
            ext_symbol.set_symbol_string_data(None)
        else:
            buf = StringBuilder()
            if address_string is not None:
                buf.append(address_string)
            if original_imported_name is not None:
                buf.append(ORIGINAL_IMPORTED_DELIMITER)
                buf.append(original_imported_name)
            ext_symbol.set_symbol_string_data(buf.toString())

class ExternalData:
    def __init__(self, string_data):
        self.original_imported_name = None
        self.address_string = None

        if string_data is not None:
            index_of = string_data.find(ORIGINAL_IMPORTED_DELIMITER)
            original_imported_name = index_of >= 0 and string_data[index_of + 1:] or None
            address_string = index_of >= 0 and string_data[:index_of] or string_data

    def get_original_imported_name(self):
        return self.original_imported_name

    def get_address(self, addr_factory):
        if self.address_string is None:
            return None
        else:
            return addr_factory.get_address(self.address_string)

class symboldb:
    pass
```

Please note that this translation may not be perfect as Python and Java have different syntax and semantics. This code might need to be adjusted based on the actual usage in your program.