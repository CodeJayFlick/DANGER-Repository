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

import os

class CockroachTestConnectionProviderSource:
    def __init__(self):
        pass

    def is_compatible_with(self, adapter_config: dict, database_adapter_factory: object) -> bool:
        return isinstance(adapter_config.get('adapter'), TxDatabaseAdapterConfig) and \
               isinstance(database_adapter_factory, PostgresDatabaseAdapterFactory)

    def create_container(self) -> JdbcDatabaseContainer:
        version = os.environ.get("IT_NESSIE_CONTAINER_COCKROACH_TAG", "v21.1.6")
        return CockroachContainer(f"cockroachdb/cockroach:{version}")

class TxDatabaseAdapterConfig:
    pass

class PostgresDatabaseAdapterFactory:
    pass

class JdbcDatabaseContainer:
    pass

class CockroachContainer(JdbcDatabaseContainer):
    def __init__(self, image: str):
        super().__init__()
        self.image = image
