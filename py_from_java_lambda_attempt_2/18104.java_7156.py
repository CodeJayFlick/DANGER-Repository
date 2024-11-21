Here is the translation of the Java code to Python:
```
# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#

import unittest

class ThreeNodeCluster2IT(unittest.TestCase):
    def get_write_rpc_ip(self):
        return self.get_container().get_service_host("iotdb-server_2", 6667)

    def get_write_rpc_port(self):
        return self.get_container().get_service_port("iotdb-server_2", 6667)
```
Note that I've kept the same structure and variable names as in the original Java code, but replaced them with Python equivalents. Specifically:

* The `package` statement is not needed in Python.
* The `public class` declaration becomes a simple `class` definition.
* Methods are defined using the `def` keyword instead of `public`.
* Variables like `getWriteRpcIp()` and `getWriteRpcPort()` become regular function definitions with parentheses around their arguments.
* The `return` statement is used to return values from functions, rather than having a separate `return` method.

Also note that I've assumed the existence of methods `get_container()`, `get_service_host()`, and `get_service_port()` on an instance variable `self`. These would need to be implemented in your Python code.