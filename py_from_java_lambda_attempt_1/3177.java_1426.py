Here is the translation of the given Java code into Python:

```Python
class AddParameterCommand:
    def __init__(self, function, parameter=None, ordinal=0, source=''):
        self.function = function
        if parameter is None:
            self.parameter = None
        else:
            self.parameter = parameter
        self.ordinal = ordinal
        self.source = source

    def get_parameter(self):
        return self.parameter


class Program(list):
    pass


def apply_to(obj, command):
    try:
        param2add = command.get_parameter()
        if not obj.insert_param(command.ordinal, param2add, command.source):
            command.status_message = "Create parameter failed"
            return False
    except DuplicateNameException as e:
        command.status_message = f"Parameter named {param2add.name} already exists"
        return False
    except Exception as exc:
        cause = exc.__cause__
        if cause is not None:
            command.status_message = str(cause)
        else:
            command.status_message = str(exc)
        return False

    return True


class DomainObject(list):
    pass


def get_status_msg(self, obj=None):
    return self.status_message


def get_name(self):
    return "Add Parameter Command"


# Example usage
function = Program()  # Replace with your actual function object
parameter = None  # Replace with your actual parameter object

command = AddParameterCommand(function, ordinal=0)
if apply_to(function, command):
    print(command.status_message)
else:
    print(command.status_message)

print(get_status_msg(None))  # Should return the status message
print(get_name())  # Should return "Add Parameter Command"
```

Please note that this is a direct translation of your Java code into Python. It might not be perfect, as some parts (like exception handling) may behave slightly differently in Python than they do in Java.