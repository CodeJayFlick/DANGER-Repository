Here is the equivalent Python code for the given Java code:

```Python
class ValueUtils:
    INCLUDE_STACK = False

    @staticmethod
    def report_err(val, cls, log_obj, attribute_name):
        message = f"expected {cls.__name__} for {attribute_name}, but got {val}"
        if ValueUtils.INCLUDE_STACK:
            print(f"{message}: {str(sys.exc_info())}")
        else:
            print(message)

    @staticmethod
    def expect_type(val, cls, log_obj, attribute_name, fallback=None, required=False):
        if val is None or not isinstance(val, cls):
            if val is not None or required:
                ValueUtils.report_err(val, cls, log_obj, attribute_name)
            return fallback
        return cls(val)

import sys

# Example usage:

ValueUtils.INCLUDE_STACK = True  # Set to False for non-debug mode

def main():
    try:
        value_utils = ValueUtils()
        val1 = "Hello"
        expected_type = str
        log_obj = None
        attribute_name = "attribute name"

        result1 = value_utils.expect_type(val1, expected_type, log_obj, attribute_name)
        print(f"Result 1: {result1}")

    except Exception as e:
        ValueUtils.report_err(None, type(e), sys.exc_info()[2], str(e))

if __name__ == "__main__":
    main()
```

Please note that Python does not have direct equivalent of Java's `enum` and some other features. The above code is an approximation based on the given Java code.