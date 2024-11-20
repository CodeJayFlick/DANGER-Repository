Here is the translation of the Java code to Python:
```
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

class ByteViewerProgramLocation:
    def __init__(self):
        # for xml restoring
        pass

    @classmethod
    def from_program(cls, program: 'Program', address: 'Address', character_offset: int) -> 'ByteViewerProgramLocation':
        return cls(program=program, address=address, offset=0, length=0, character_offset=character_offset)

class Program:
    # This is a placeholder for the actual Program class
    pass

class Address:
    # This is a placeholder for the actual Address class
    pass
```
Note that I had to make some assumptions about the `Program` and `Address` classes since they are not defined in the original Java code. In Python, we don't have direct equivalents of these classes, so I left them as placeholders.

Also, I used a class method (`@classmethod`) for the constructor-like method `from_program`, which is equivalent to the Java constructor with multiple parameters.