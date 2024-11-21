Here is the translation of the Java code to Python:
```
import json

class AwsHttpApiV2SecurityContextWriter:
    def write_security_context(self, event: dict, lambda_context: dict) -> dict:
        return {"lambda_context": lambda_context, "event": event}

# Example usage
if __name__ == "__main__":
    event = {"key1": "value1", "key2": "value2"}
    lambda_context = {"function_name": "my_function", "invoked_function_arn": "arn:aws:lambda:us-west-2:123456789012:function:my-function"}
    security_context = AwsHttpApiV2SecurityContextWriter().write_security_context(event, lambda_context)
    print(json.dumps(security_context))
```
Note that I've made the following changes:

* Removed the Java-specific imports and package declarations.
* Replaced the `public` access modifier with no access modifier (i.e., just a class definition).
* Changed the method signature to use Python's built-in dictionary type instead of Java's `SecurityContext`.
* Simplified the implementation by returning a new dictionary that contains the lambda context and event data.

The resulting code is a simple Python class that takes two dictionaries as input, combines them into a single dictionary, and returns it.