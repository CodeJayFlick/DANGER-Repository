Here is the translation of the Java code to Python:
```
import xml.etree.ElementTree as ET

class LambdaHandler:
    def __init__(self):
        self.handler = None
        self.is_initialized = False

    def handle_request(self, aws_proxy_request: dict, context: dict) -> dict:
        if not self.is_initialized:
            try:
                wc = ET.parse("staticAppContext.xml").getroot()
                self.handler = SpringLambdaContainerHandler(aws_proxy_request, context)
                self.is_initialized = True
            except Exception as e:
                print(f"Error initializing handler: {e}")
                return None

        res = self.handler.proxy(aws_proxy_request, context)
        return res


class SpringLambdaContainerHandler:
    def __init__(self, aws_proxy_request: dict, context: dict):
        pass  # Not implemented in Python equivalent

    @staticmethod
    def get_aws_proxy_handler(wc) -> object:
        raise NotImplementedError("Not implemented")
```
Note that I had to make some assumptions about the Java code:

* The `SpringLambdaContainerHandler` class is not a standard Python library, so I created a placeholder implementation.
* The `AwsProxyRequest` and `AwsProxyResponse` classes are also not standard Python libraries, so I represented them as dictionaries in the Python equivalent.

Also, keep in mind that this translation may not be perfect, as Java and Python have different syntax and semantics. You may need to modify the code further to make it work correctly with your specific use case.