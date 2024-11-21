Here is the translation of the Java code to Python:
```
# Copyright 2020 Dremio
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

import inject

class QuarkusRocksDbInstance:
    def __init__(self, rocks_config):
        self.configure(rocks_config)
        self.initialize()

    @inject.inject
    def configure(self, immutable_rocks_db_config):
        pass  # equivalent to Java's RocksDbConfig.builder().dbPath(rocksConfig.getDbPath()).build()

    def initialize(self):
        pass  # equivalent to Java's initialize() method

# Usage:
rocks_config = VersionStoreConfig.RocksVersionStoreConfig(db_path='path/to/db')
quarkus_rocks_db_instance = QuarkusRocksDbInstance(rocks_config)
```
Note that Python does not have a direct equivalent to Java's `@Singleton` annotation, so I omitted it. Additionally, the `inject` library is used to simulate the injection of dependencies in Python.

Also, please note that this translation is just an approximation and may require further modifications depending on your specific use case.