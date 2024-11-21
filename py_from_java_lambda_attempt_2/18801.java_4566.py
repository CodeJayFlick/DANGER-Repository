Here is the translation of the Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

class NessieConfigConstants:
    CONF_NESSIE_URI = 'nessie.uri'
    @property
    def CONF_NESSIE_USERNAME(self):
        """@deprecated "basic" HTTP authentication is not considered secure. Use #CONF_NESSIE_AUTH_TOKEN instead."""
        return 'nessie.authentication.username'

    @property
    def CONF_NESSIE_PASSWORD(self):
        """@deprecated "basic" HTTP authentication is not considered secure. Use #CONF_NESSIE_AUTH_TOKEN instead."""
        return 'nessie.authentication.password'

    CONF_NESSIE_AUTH_TOKEN = 'nessie.authentication.token'
    CONF_NESSIE_AWS_REGION = 'nessie.authentication.aws.region'
    @property
    def CONF_NESSIE_AWS_PROFILE(self):
        """(optional)"""
        return 'nessie.authentication.aws.profile'

    CONF_NESSIE_AUTH_TYPE = 'nessie.authentication.type'
    CONF_NESSIE_REF = 'nessie.ref'
    CONF_NESSIE_TRACING = 'nessie.tracing'

    def __init__(self):
        pass
```

Note that Python does not have direct equivalent of Java's `@Deprecated` annotation. Instead, I've added a docstring to the properties to indicate they are deprecated.