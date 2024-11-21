# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

import tempfile

class SerializableListTest:
    ITERATION_TIMES = 10000  # make sure serialize() & deserialize() can be triggered
    MEMORY_USAGE_LIMIT_IN_MB = 100.0
    CACHE_SIZE = 3
    QUERY_ID = 0
    INTERNAL_ROW_RECORD_LIST_CAPACITY = 8

    def setUp(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pass

    def tearDown(self):
        pass
