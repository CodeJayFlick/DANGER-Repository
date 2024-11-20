Here is a translation of the provided Java code into equivalent Python:

```Python
class FunctionTableModel:
    LOCATION_COL_WIDTH = 50
    
    NAME_ COL = 0
    LOCATION_ COL = 1
    PROTOTYPE_ COL = 2

    def __init__(self, tool, program):
        self.function_mgr = None
        super().__init__("Functions", tool, program)

    @property
    def function_manager(self):
        return self.function_mgr

    @function_manager.setter
    def function_manager(self, value):
        if value is not None:
            self.function_mgr = value.get_function_manager()
        else:
            self.function_mgr = None

    def create_table_column_descriptor(self):
        descriptor = TableColumnDescriptor()

        name_column = NameTableColumn()
        address_column = AddressTableColumn()
        signature_column = FunctionSignatureTableColumn()
        body_size_column = FunctionBodySizeTableColumn()
        tag_column = FunctionTagTableColumn()
        is_inline_column = IsFunctionInlineTableColumn()
        non_returning_column = IsFunctionNonReturningTableColumn()
        varargs_column = IsFunctionVarargsTableColumn()
        custom_storage_column = IsFunctionCustomStorageTableColumn()

        descriptor.add_visible_column(name_column)
        descriptor.add_visible_column(address_column, 1, True)
        descriptor.add_visible_column(signature_column)
        descriptor.add_hidden_column(body_size_column)
        descriptor.add_hidden_column(tag_column)
        descriptor.add_hidden_column(is_inline_column)
        descriptor.add_hidden_column(non_returning_column)
        descriptor.add_hidden_column(varargs_column)
        descriptor.add_hidden_column(custom_storage_column)

        return descriptor

    def reload(self, program):
        self.set_program(program)
        if program is not None:
            self.function_manager = program.get_function_manager()
        else:
            self.function_manager = None
        self.reload()

    @property
    def key_count(self):
        if self.function_manager is None:
            return 0
        return self.function_manager.get_function_count()

    def do_load(self, accumulator, monitor):
        it = LongIterator.EMPTY
        if self.function_manager is not None:
            it = FunctionKeyIterator(self.function_manager)
        
        monitor.initialize(self.key_count())
        progress = 0
        while it.has_next():
            monitor.set_progress(progress++)
            monitor.check_canceled()
            key = it.next()
            function = self.function_manager.get_function(key)
            accumulator.add(FunctionRowObject(function))
    
    class FunctionKeyIterator:
        def __init__(self, function_mgr):
            self.itr = function_mgr.get_functions(True)

        @property
        def has_next(self):
            if self.itr is None:
                return False
            return self.itr.has_next()

        def next(self):
            function = self.itr.next()
            return function.id

    class FunctionRowObject:
        def __init__(self, f):
            self.function = f

        @property
        def key(self):
            return self.function.id

    def add_object(self, obj):
        pass  # Add the object to your data structure or UI component.

    def remove_object(self, obj):
        pass  # Remove the object from your data structure or UI component.

    def update_object(self, obj):
        pass  # Update the object in your data structure or UI component.

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value):
        if value is not None:
            self.function_manager = value.get_function_manager()
        else:
            self.function_manager = None
        self._program = value

    class NameTableColumn:
        def get_column_name(self):
            return "Name"

        def get_value(self, row_object, settings, program, sp):
            function = row_object.function
            if function is None:
                return None
            return function.name


class FunctionRowObject:
    pass  # This class should be defined in the original code.

class AddressTableColumn:
    pass  # This class should be defined in the original code.

class FunctionSignatureTableColumn:
    pass  # This class should be defined in the original code.

class FunctionBodySizeTableColumn:
    pass  # This class should be defined in the original code.

class FunctionTagTableColumn:
    pass  # This class should be defined in the original code.

class IsFunctionInlineTableColumn:
    pass  # This class should be defined in the original code.

class IsFunctionNonReturningTableColumn:
    pass  # This class should be defined in the original code.

class IsFunctionVarargsTableColumn:
    pass  # This class should be defined in the original code.

class IsFunctionCustomStorageTableColumn:
    pass  # This class should be defined in the original code.
```

This Python translation is based on the provided Java code. However, please note that some classes and methods are not implemented as they were missing from the given Java code.