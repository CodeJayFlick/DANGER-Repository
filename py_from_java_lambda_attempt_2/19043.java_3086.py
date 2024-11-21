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

import abc

class InmemoryConfig:
    pass  # todo: implement this class in Python

class AbstractTestConnectionProviderSource(metaclass=abc.ABCMeta):
    @abstractmethod
    def isCompatibleWith(self, adapter_config, database_adapter_factory) -> bool:
        ...

    @abstractmethod
    def createDefaultConnectionProviderConfig(self) -> InmemoryConfig:
        return InmemoryConfig()

    @abstractmethod
    def createConnectionProvider(self) -> 'InmemoryStore':
        return InmemoryStore()

class InmemoryTestConnectionProviderSource(AbstractTestConnectionProviderSource):
    def isCompatibleWith(self, adapter_config: DatabaseAdapterConfig, database_adapter_factory: DatabaseAdapterFactory) -> bool:
        return isinstance(adapter_config, NonTransactionalDatabaseAdapterConfig) and isinstance(database_adapter_factory, InmemoryDatabaseAdapterFactory)

    def createDefaultConnectionProviderConfig(self) -> InmemoryConfig:
        return InmemoryConfig()

    def createConnectionProvider(self) -> 'InmemoryStore':
        return InmemoryStore()
```
Note that I did not implement the `InmemoryConfig` class in Python as it was left abstract in Java. You will need to define this class or its equivalent in your Python code.

Also, I used the `abc` module from Python's standard library to create an abstract base class (`AbstractTestConnectionProviderSource`) and a concrete subclass (`InmemoryTestConnectionProviderSource`).