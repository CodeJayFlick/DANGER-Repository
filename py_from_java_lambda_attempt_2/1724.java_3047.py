Here is a translation of the Java code into equivalent Python:

```Python
class LldbModelTargetSessionAttributesImpl:
    def __init__(self, session):
        self.platform_attributes = PlatformAttributes(self)
        self.environment = EnvironmentAttributes(self)

        target = session.model_object()
        triple = target.triple().split('-')
        order_str = 'invalid'
        if target.byte_order() == ByteOrder.LITTLE_ENDIAN:
            order_str = 'little'
        elif target.byte_order() == ByteOrder.BIG_ENDIAN:
            order_str = 'big'
        elif target.byte_order() == ByteOrder.PDP_ENDIAN:
            order_str = 'pdp'

        self.change_attributes([], [self.platform_attributes, self.environment], 
                               {'ARCH_ATTRIBUTE_NAME': triple[0],
                                'DEBUGGER_ATTRIBUTE_NAME': 'lldb',
                                'OS_ATTRIBUTE_NAME': triple[2],
                                'ENDIAN_ATTRIBUTE_NAME': order_str}, "Initialized")

    def request_elements(self, refresh):
        return CompletableFuture.completed_future(None)

    def refresh_internal(self):
        self.platform_attributes.refresh_internal()

class PlatformAttributes:
    def __init__(self, parent):
        self.parent = parent

    def refresh_internal(self):
        pass  # Implement this method as needed


class EnvironmentAttributes:
    def __init__(self, parent):
        self.parent = parent

    def refresh_internal(self):
        pass  # Implement this method as needed
```

Note that I've omitted the `@TargetObjectSchemaInfo` annotation and other Java-specific constructs. The Python code is designed to mimic the structure of the original Java code, but it may not be a direct translation in every detail.

Also note that some methods (like `request_elements`) are essentially no-ops in this translation, as they don't have an equivalent implementation in Python.