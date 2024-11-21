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

import asyncio

class RestConfigResource:
    def __init__(self):
        self.config = None

    async def set_config(self, config: 'ServerConfig'):
        if not isinstance(config, ServerConfig):
            raise TypeError("config must be an instance of ServerConfig")
        self.config = ConfigApiImpl(config)

    async def get_config(self) -> 'NessieConfiguration':
        return await self.config.get_config()

class ConfigApiImpl:
    def __init__(self, config: 'ServerConfig'):
        if not isinstance(config, ServerConfig):
            raise TypeError("config must be an instance of ServerConfig")
        self.config = config

    async def get_config(self) -> 'NessieConfiguration':
        # implement the logic to retrieve the configuration
        pass

class NessieConfiguration:
    # define your custom class here
    pass

# Example usage:
async def main():
    server_config = ServerConfig()  # create an instance of ServerConfig
    rest_config_resource = RestConfigResource()
    await rest_config_resource.set_config(server_config)
    config = await rest_config_resource.get_config()

if __name__ == "__main__":
    asyncio.run(main())
