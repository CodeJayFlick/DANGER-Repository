Here is the translation of the given Java code into equivalent Python:

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

import unittest

class ITVersionStorePostgres(unittest.IsolatedTestCase):
    @unittest.skipIf(not 'it.nessie.dbs' in os.environ.get('SYSTEM_PROPERTIES', '') or not re.search(r'.*postgres.*', os.environ['it.nessie.dbs']):
    def test_version_store_postgres(self):
        pass

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalents for Java's annotations like `@EnabledIfSystemProperty`, `@NessieDbAdapterName` and `@NessieExternalDatabase`. These are used to configure the test environment. In this translation, I've replaced them with a simple conditional statement using Python's built-in modules (`os` and `re`) that checks if certain system properties match specific patterns.