# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import abc

class NessieExternalDatabase:
    def __init__(self, provider):
        self.provider = provider

@NessieExternalDatabase(RocksTestConnectionProviderSource)
class TestVersionStoreRocks(abc.ABCMeta('AbstractVersionStoreTest')):
    pass
