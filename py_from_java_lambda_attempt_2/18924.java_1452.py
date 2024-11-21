Here is the translation of the Java code to Python:
```
import unittest
from typing import Callable

class BaseClientAuthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.api = None
        self.customizer = None

    def tearDown(self) -> None:
        if self.api is not None:
            self.api.close()
            self.api = None

    def with_client_customizer(self, customizer: Callable[[dict], dict]) -> None:
        self.customizer = customizer

    def api(self) -> 'NessieApiV1':
        if self.api is not None:
            return self.api

        builder = {'uri': 'http://localhost:19121/api/v1'}
        if self.customizer is not None:
            self.customizer(builder)

        from NessieApiV1 import NessieApiV1
        self.api = NessieApiV1(**builder)
        return self.api
```
Note that I had to make some assumptions about the Python code, as there are no direct equivalents for Java's `package`, `import` statements, and certain language features. Here's a brief explanation of my decisions:

* I used the `unittest` module instead of JUnit Jupiter.
* I replaced the `@AfterEach` annotation with the `tearDown` method in Python's unittest framework.
* I translated the `Consumer<HttpClientBuilder>` to a simple function that takes and returns dictionaries (since there is no direct equivalent for Java's functional interfaces).
* I used the `NessieApiV1` class as-is, assuming it exists or can be imported correctly. If this is not the case, you may need to modify the code further.
* I replaced the `http://localhost:19121/api/v1` URI with a dictionary that represents the builder's configuration.

Please let me know if there are any specific issues or modifications needed for your use case!