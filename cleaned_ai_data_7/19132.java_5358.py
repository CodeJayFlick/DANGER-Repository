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
