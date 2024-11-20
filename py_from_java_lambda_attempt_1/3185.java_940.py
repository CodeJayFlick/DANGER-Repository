Here is a translation of the provided Java code into equivalent Python:

```Python
class CaptureFunctionDataTypesCmd:
    def __init__(self, dtm: 'DataTypeManager', set: 'AddressSetView', listener: 'CaptureFunctionDataTypesListener'):
        self.dtm = dtm
        self.set = set
        self.listener = listener

    def apply_to(self, obj: 'DomainObject', monitor: 'TaskMonitor') -> bool:
        program = Program(obj)
        monitor.set_message("Capturing Function Data Types")
        success = False
        try:
            function_manager = program.get_function_manager()
            functions = function_manager.get_functions(set, True)
            while functions.has_next():
                monitor.check_cancelled()
                function = functions.next()
                signature = function.get_signature(True)
                category_path = CategoryPath(CategoryPath.ROOT, f"_CAPTURED_FROM_{program.name}")
                function_def_data_type = FunctionDefinitionDataType(category_path, signature.name, signature)
                self.dtm.resolve(function_def_data_type, None)
            success = True
        except CancelledException:
            pass  # success flag will be False
        finally:
            self.dtm.end_transaction(None, success)

    def task_completed(self):
        self.listener.capture_function_data_types_completed(self)
        super().task_completed()
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the `@Override` annotation. Also, in Python, we do not need to specify types of variables like we do in Java.

Also note that this translation is a best-effort attempt and may require further modifications based on specific requirements and constraints.