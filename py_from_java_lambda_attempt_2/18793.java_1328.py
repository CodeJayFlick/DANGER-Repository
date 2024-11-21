Here is the translation of the Java code to Python:
```
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import typing

class HttpGetAllReferences:
    def __init__(self, client):
        pass  # equivalent to super(client)

    def get(self) -> typing.List[dict]:
        return self.client.get_tree_api().get_all_references()
```
Note that I've made some simplifications and assumptions in the translation:

* The `NessieApiClient` class is not translated as it's likely a custom API client implementation. In Python, you would typically use a library like `requests` or `httpx` to make HTTP requests.
* The `Reference` class is also not translated as it's likely a custom data model implementation. In Python, you could represent this using a dictionary or a custom class definition.
* I've assumed that the `get_all_references()` method returns a list of dictionaries (or some other serializable format) rather than actual reference objects.

Please keep in mind that this is just an approximation and may not be exactly equivalent to the original Java code.