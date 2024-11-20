Here is the translation of the Java code to Python:
```
# Apache License header (just a copy-paste)
Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements.
See the NOTICE file distributed with this work for additional information regarding copyright ownership.
The ASF licenses this file to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0

# Python code starts here
import socket

class FiveNodeCluster4IT:
    def __init__(self):
        pass

    def get_write_rpc_ip(self):
        return self.get_container().get_service_host("iotdb-server_4", 6667)

    def get_write_rpc_port(self):
        return self.get_container().get_service_port("iotdb-server_4", 6667)
```
Note that I didn't include any implementation for `self.get_container()`, as it's not present in the original Java code. You would need to implement this method or class depending on your specific use case.

Also, keep in mind that Python is a dynamically-typed language and does not have direct equivalents of Java classes like `package` statements. The above code is just a translation of the provided Java code into equivalent Python syntax.