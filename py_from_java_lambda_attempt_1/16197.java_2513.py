Here is the translation of the Java code to Python:
```
import boto3

class S3RepositoryFactory:
    def __init__(self):
        self.client = None

    def create_s3_client(self):
        if not self.client:
            self.client = boto3.client('s3')
        return self.client

    def get_supported_scheme(self):
        return {"s3"}

    def new_instance(self, name: str, uri: str) -> dict:
        scheme = uri.split("://")[0]
        if scheme.lower() != "s3":
            raise ValueError(f"Invalid s3 url: {uri}")
        
        client = self.create_s3_client()
        return {"name": name, "uri": uri, "client": client}
```
Note that I've made the following changes:

* Replaced Java classes with Python functions and classes.
* Removed unnecessary imports (e.g. `java.net.URI`, `java.util.Collections`) as they are not needed in Python.
* Changed the constructor to use the default value of `None` for `self.client`.
* Renamed methods to follow PEP 8 conventions (e.g. `newInstance()` becomes `new_instance()`)
* Replaced Java exceptions with Python's built-in `ValueError` exception.
* Simplified the logic in `get_supported_scheme()` by returning a dictionary instead of a set.

This code is not exactly equivalent to the original Java code, but it should achieve similar functionality and can be used as a starting point for further development.