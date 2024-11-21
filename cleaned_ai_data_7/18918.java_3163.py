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

import io

class VersionStoreFactory:
    """ Factory interface for creating version store instances. """

    def new_store(self, worker: 'io.StoreWorker', server_config) -> 'io.VersionStore':
        """
        Creates a new store using the provided worker.
        
        :param value_type
        :param metadata_type
        :param value_type_enum
        :param worker: The worker instance
        :return: A store instance
        :raises IOException: If an exception occurs during store instantiation
        """
        # Note that Python does not have a direct equivalent to Java's generics,
        # so we'll use type hints instead. This allows for static analysis and IDE completion.
        value_type = None  # Replace with actual type hinting if needed
        metadata_type = None  # Replace with actual type hinting if needed
        value_type_enum = None  # Replace with actual type hinting if needed

        try:
            return io.VersionStore(worker, server_config)
        except Exception as e:
            raise IOException("Exception occurred during store instantiation") from e
