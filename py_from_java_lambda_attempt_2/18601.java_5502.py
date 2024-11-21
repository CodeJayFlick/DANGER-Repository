Here is the equivalent Python code:

```Python
class AwsProxyServletResponseSupplier:
    def __init__(self):
        self.current_request = None

    #-------------------------------------------------------------
    # Implementation - Factory
    #-------------------------------------------------------------

    def get(self) -> 'HttpServletResponse':
        return self.get_response()

    def get_response(self) -> 'HttpServletResponse':
        if not hasattr(self, '_response'):
            setattr(self, '_response', self.current_request[JERSEY_SERVLET_RESPONSE_PROPERTY])
        return getattr(self, '_response')
```

Note that Python does not have a direct equivalent to Java's `Supplier` interface. Instead, we can define our own class with a single method (`get`) which returns the desired value.

Also note that in Python, there is no need for explicit type declarations like `public`, `private`, or `@Override`. The syntax and structure of the code are different from those used in Java.