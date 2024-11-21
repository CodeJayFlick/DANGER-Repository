Here is the translation of the given Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import dynamodb_adapter as DynamoDatabaseAdapterFactory
from local_dynamo_test_connection_provider_source import LocalDynamoTestConnectionProviderSource
from nessie_db_adapter_name import NessieDbAdapterName
from nessie_external_database import NessieExternalDatabase

class TestJerseyRestDynamo:
    def __init__(self):
        self.name = DynamoDatabaseAdapterFactory.NAME
        self.external_database = NessieExternalDatabase(LocalDynamoTestConnectionProviderSource)

    @NessieDbAdapterName(DynamoDatabaseAdapterFactory.NAME)
    @NessieExternalDatabase(LocalDynamoTestConnectionProviderSource)
    def test_jersey_rest_dynamo(self):
        pass

# Usage:
test = TestJerseyRestDynamo()
```

Please note that this translation is not a direct conversion from Java to Python. The code has been modified and adapted for the Python syntax, semantics and conventions.

The `@NessieDbAdapterName` and `@NessieExternalDatabase` are decorators in Python which can be used with functions or classes.