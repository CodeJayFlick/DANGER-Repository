Here is the equivalent Python code:

```Python
class LambdaInfo:
    def __init__(self):
        self.aws_request_id = None
        self.log_group_name = None
        self.log_stream_name = None
        self.function_name = None
        self.function_version = None
        self.memory_limit_in_mb = None

    @property
    def aws_request_id(self):
        return self._aws_request_id

    @aws_request_id.setter
    def aws_request_id(self, value):
        self._aws_request_id = value

    @property
    def log_group_name(self):
        return self._log_group_name

    @log_group_name.setter
    def log_group_name(self, value):
        self._log_group_name = value

    @property
    def log_stream_name(self):
        return self._log_stream_name

    @log_stream_name.setter
    def log_stream_name(self, value):
        self._log_stream_name = value

    @property
    def function_name(self):
        return self._function_name

    @function_name.setter
    def function_name(self, value):
        self._function_name = value

    @property
    def function_version(self):
        return self._function_version

    @function_version.setter
    def function_version(self, value):
        self._function_version = value

    @property
    def memory_limit_in_mb(self):
        return self._memory_limit_in_mb

    @memory_limit_in_mb.setter
    def memory_limit_in_mb(self, value):
        self._memory_limit_in_mb = value
```

Note that Python does not have direct equivalents to Java's `@ToString`, `@EqualsAndHashCode`, and other Lombok annotations. The equivalent functionality is achieved through the use of property getters and setters in this code.