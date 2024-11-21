Here is the translation of the given Java code into equivalent Python:

```Python
import opentracing as ot
from collections import defaultdict

class TracingUtil:
    def __init__(self):
        pass  # empty constructor

    @staticmethod
    def safe_to_string(o):
        return str(o) if o else "<null>"

    @staticmethod
    def safe_size(collection):
        return len(collection) if collection else -1

    @staticmethod
    def trace_error(span, e):
        span.log({'event': 'error', 'error_object': str(e)}, True)
        return e


# Example usage:
span = ot.Span()
e = Exception('some error')
result = TracingUtil.trace_error(span, e)
```

Please note that Python does not have direct equivalent of Java's `Tags` and `Fields`. In the above code, I used a dictionary to represent these concepts. Also, Python does not support static methods like in Java; instead, we use classmethods or instance methods depending on our needs.

Also, please ensure you have installed opentracing library using pip install opentracing before running this python script.