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

class QuarkusServerConfig:
    def __init__(self):
        self.default_branch = 'main'
        self.send_stacktrace_to_client = False

    @property
    def default_branch(self):
        return self._default_branch

    @default_branch.setter
    def default_branch(self, value):
        if not isinstance(value, str):
            raise TypeError('Default branch must be a string')
        self._default_branch = value

    @property
    def send_stacktrace_to_client(self):
        return self._send_stacktrace_to_client

    @send_stacktrace_to_client.setter
    def send_stacktrace_to_client(self, value):
        if not isinstance(value, bool):
            raise TypeError('Send stack trace to client must be a boolean')
        self._send_stacktrace_to_client = value
```
Note that Python does not have direct equivalents for Java's `@ConfigProperties` and `@ConfigProperty` annotations. Instead, we use Python's built-in property decorator (`@property`) to create getter/setter methods for the configuration properties.

Also, note that in Python, it is common practice to use underscore-prefixed variables (e.g., `_default_branch`, `_send_stacktrace_to_client`) to indicate internal implementation details and avoid naming conflicts with public attributes.