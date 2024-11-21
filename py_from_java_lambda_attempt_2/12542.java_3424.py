Here's a translation of the Java interface into Python:

```Python
class Function:
    def __init__(self):
        self.name = None
        self.program = None
        self.comment = ''
        self.repeatable_comment = ''
        self.entry_point = None
        self.return_type = None
        self.parameters = []
        self.local_variables = []
        self.variables = []
        self.custom_variable_storage = False
        self.calling_convention_name = 'default'
        self.thunked_function = None

    def get_name(self):
        return self.name

    def set_name(self, name: str) -> None:
        if not isinstance(name, str):
            raise ValueError('Name must be a string')
        self.name = name

    def get_calling_convention_name(self):
        return self.calling_convention_name

    def set_calling_convention_name(self, calling_convention_name: str) -> None:
        if not isinstance(calling_convention_name, str):
            raise ValueError('Calling convention name must be a string')
        self.calling_convention_name = calling_convention_name

    def get_comment(self):
        return self.comment

    def set_comment(self, comment: str) -> None:
        if not isinstance(comment, str):
            raise ValueError('Comment must be a string')
        self.comment = comment

    def get_repeatable_comment(self):
        return self.repeatable_comment

    def set_repeatable_comment(self, repeatable_comment: str) -> None:
        if not isinstance(repeatable_comment, str):
            raise ValueError('Repeatable comment must be a string')
        self.repeatable_comment = repeatable_comment

    def get_entry_point(self):
        return self.entry_point

    def set_entry_point(self, entry_point: 'Address') -> None:
        self.entry_point = entry_point

    def get_return_type(self):
        return self.return_type

    def set_return_type(self, return_type: 'DataType', source: str) -> None:
        if not isinstance(return_type, DataType):
            raise ValueError('Return type must be a data type')
        self.return_type = return_type
        # Add code to apply the source to the overall function signature and parameter symbols

    def get_stack_frame(self):
        pass  # This method is not implemented in Python

    def set_stack_purge_size(self, purge_size: int) -> None:
        if not isinstance(purge_size, int):
            raise ValueError('Stack purge size must be an integer')
        self.stack_purge_size = purge_size

    def get_tags(self):
        pass  # This method is not implemented in Python

    def add_tag(self, name: str) -> bool:
        if not isinstance(name, str):
            raise ValueError('Tag name must be a string')
        return True  # Add code to apply the tag and check for conflicts with existing tags

    def remove_tag(self, name: str) -> None:
        pass  # This method is not implemented in Python

    def get_parameter_count(self):
        return len(self.parameters)

    def has_var_args(self):
        return False  # This method is not implemented in Python

    def set_var_args(self, has_var_args: bool) -> None:
        self.has_var_args = has_var_args

    def is_inline(self):
        return False  # This method is not implemented in Python

    def set_inline(self, is_inline: bool) -> None:
        self.is_inline = is_inline

    def get_thunked_function(self, recursive: bool):
        if not isinstance(recursive, bool):
            raise ValueError('Recursive must be a boolean')
        return self.thunked_function  # This method does not implement the full functionality of its Java counterpart

    def promote_local_user_labels_to_global(self) -> None:
        pass  # This method is not implemented in Python
```

Please note that this translation may contain some simplifications and omissions.