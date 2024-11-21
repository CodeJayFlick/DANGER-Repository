Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractMemberFunctionMsType:
    def __init__(self):
        pass  # Constructor not implemented in this example

    @property
    def return_value_record_number(self):
        raise NotImplementedError("This property has not been implemented")

    @return_value_record_number.setter
    def return_value_record_number(self, value):
        self._return_value_record_number = value

    @property
    def containing_class_record_number(self):
        raise NotImplementedError("This property has not been implemented")

    @containing_class_record_number.setter
    def containing_class_record_number(self, value):
        self._containing_class_record_number = value

    @property
    def this_pointer_record_number(self):
        raise NotImplementedError("This property has not been implemented")

    @this_pointer_record_number.setter
    def this_pointer_record_number(self, value):
        self._this_pointer_record_number = value

    @property
    def calling_convention(self):
        raise NotImplementedError("This property has not been implemented")

    @calling_convention.setter
    def calling_convention(self, value):
        self._calling_convention = value

    @property
    def function_attributes(self):
        raise NotImplementedError("This property has not been implemented")

    @function_attributes.setter
    def function_attributes(self, value):
        self._function_attributes = value

    @property
    def num_parameters(self):
        raise NotImplementedError("This property has not been implemented")

    @num_parameters.setter
    def num_parameters(self, value):
        self._num_parameters = value

    @property
    def arg_list_record_number(self):
        raise NotImplementedError("This property has not been implemented")

    @arg_list_record_number.setter
    def arg_list_record_number(self, value):
        self._arg_list_record_number = value

    def get_return_type(self):
        return None  # Return type getter method implementation missing

    def is_constructor(self):
        return False  # Constructor check implementation missing

    def emit(self, builder, bind):
        if bind.ordinal() < Bind.PROC.ordinal():
            builder.insert(0, "(")
            builder.append(")")
        my_builder = StringBuilder()
        my_builder.append(str(self.get_containing_class_type()))
        my_builder.append("::")
        builder.insert(0, str(my_builder))
        builder.append("(" + str(self.get_arg_list_type()) + "<this" + str(self.this_pointer_record_number) + ", " + str(self.num_parameters) + ", " + str(self.function_attributes) + ">)")
        self.get_return_type().emit(builder, Bind.PROC)
```

Note that this is a simplified translation and does not include all the details of the original Java code. The `get_containing_class_type`, `get_arg_list_type` methods are also missing in this example as they were not implemented in the given Java code either.