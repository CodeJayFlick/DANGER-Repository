Here is the translation of the given Java code into equivalent Python:

```Python
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

class DummyDebugInfo:
    """This class is an extension of PdbOldDebugInfo, whose sole purpose 
       is to allow for testing of internal components of AbstractPdb classes.  
       It is not part of the production PDB Reader.
    """

    def __init__(self, pdb):
        super().__init__(pdb, 0)

# Package-Protected Internals
class PdbOldDebugInfo:
    pass

class AbstractPdb:
    pass
```

Please note that Python does not have direct equivalent to Java's package and import statements. The above code is a simple translation of the given Java code into equivalent Python.