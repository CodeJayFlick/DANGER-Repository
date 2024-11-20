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

class ITDatabaseAdapterPostgres(unittest.IsolatedTestCase):
    @unittest.skipIf("it.nessie.dbs" not in os.environ or ".*postgres.*" not in os.environ["it.nessie.dbs"], reason="Not a Postgres test")
    def test_database_adapter_postgres(self):
        pass

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have direct equivalents for Java's annotations (`@EnabledIfSystemProperty`, `@NessieDbAdapterName`, and `@NessieExternalDatabase`). The equivalent in this code is the use of a conditional skip test, which skips the test if certain conditions are met.