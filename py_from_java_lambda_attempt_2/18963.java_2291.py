Here is the translation of the given Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import unittest
from quarkus_test import QuarkusTest
from test_profile import TestProfile
from resteasy_test import AbstractResteasyTest
from server.profiles.quarkus_test_profile_mongo import QuarkusTestProfileMongo


class TestResteasyMongo(AbstractResteasyTest):
    @QuarkusTest
    @TestProfile(QuarkusTestProfileMongo)
    def test_rest_easy_mongo(self):
        pass

if __name__ == "__main__":
    unittest.main()
```

Please note that the equivalent Python code may not be a direct translation, as Java and Python are different programming languages with their own syntax.