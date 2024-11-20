# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import rocksdb as RocksDatabaseAdapterFactory
from extension import NessieDbAdapterName, NessieExternalDatabase

class TestJerseyRestRocks:
    @NessieDbAdapterName(RocksDatabaseAdapterFactory.NAME)
    @NessieExternalDatabase(RocksTestConnectionProviderSource.__name__)
    def __init__(self):
        super().__init__()
