Here is the translation of the given Java code into equivalent Python:

```Python
class TestedTracingStoreInvocation:
    def __init__(self, op_name: str, failures: list):
        self.op_name = op_name
        self.tags = {}
        self.logs = []
        self.function = None
        self.result = None
        self.failures = failures

    def tag(self, key: str, value) -> 'TestedTracingStoreInvocation':
        self.tags[key] = value
        return self

    def log(self, log: dict) -> 'TestedTracingStoreInvocation':
        self.logs.append(log)
        return self

    def function(self, func, result):
        self.function = func
        self.result = result
        return self

    def method(self, method):
        if self.function is None:
            self.function = lambda x: method(x) or None
        else:
            self.function = lambda x: (method(x),)
        return self

def to_arguments(version_store_functions):
    arguments_stream = []
    for invocation in version_store_functions:
        normal_execs = [(invocation, None)]
        exceptional_execs = [(ex,) for ex in invocation.failures]
        arguments_stream.extend(normal_execs + exceptional_execs)
    return [Arguments(*args) for args in arguments_stream]

class Arguments:
    def __init__(self, *args):
        self.args = list(args)

    @property
    def op_name(self):
        return self.args[0].op_name

    @property
    def tags(self):
        return self.args[0].tags

    @property
    def logs(self):
        return [log for log in self.args[0].logs]

    @property
    def function(self):
        return self.args[0].function

    @property
    def result(self):
        return self.args[0].result

    @property
    def failures(self):
        return list(map(lambda x: x, self.args[1:]))

class ArgumentsStream:
    pass  # Not implemented in this translation.