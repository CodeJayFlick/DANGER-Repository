Here is the equivalent Python code:

```Python
class AwsProxyServletContextSupplier:
    def __init__(self):
        self.current_request = None

    def get(self) -> dict:
        return self.get_servlet_context()

    def get_servlet_context(self) -> dict:
        if not self.current_request:
            raise Exception("Could not find servlet request in context")

        ctx = self.current_request.environ['wsgiorgoriginaluri']
        return ctx
```

Note that the `Supplier` interface is equivalent to a Python function, and the `ServletContext` class is equivalent to a Python dictionary. The `ContainerRequest` object has been replaced with an instance variable `current_request`, which represents the current request in the application.

The code also assumes that you are using Flask or Django as your web framework, since they provide support for handling HTTP requests and responses through their built-in objects (`request` and `response`).