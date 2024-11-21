Here is the translation of the given Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import http.client as http_client

class NessieAuthentication:
    """Base interface for different authentication methods like 'basic' (username + plain password), bearer token, etc.

    Implementations of this class do have to implement transport specific implementations. For example,
    the Nessie HTTP based transport implements the HttpAuthentication.
    """

pass
```

Please note that Python does not support interfaces in the same way as Java. Instead, we use abstract base classes (ABCs) or protocols from the `typing` module to define a contract for implementing classes.