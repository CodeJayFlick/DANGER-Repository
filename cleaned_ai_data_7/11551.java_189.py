# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

class VarnodeData:
    def __init__(self):
        self.space = None  # equivalent to AddressSpace in Java
        self.offset = 0  # equivalent to long offset in Java
        self.size = 0  # equivalent to int size in Java

import ghidra.program.model.address.AddressSpace  # assuming this is a Python module or class

# Note: In Python, we don't need explicit getters and setters like in Java.
