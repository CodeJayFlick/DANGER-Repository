Here is the translation of the given Java code into equivalent Python:

```Python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions
# and limitations under the License.

import numpy as np

class OutputShapeTest:
    manager = None

    def setup_manager(self):
        self.manager = NDManager.new_base_manager()

    def teardown_manager(self):
        if self.manager is not None:
            self.manager.close()
```

Please note that Python does not have direct equivalent of Java's annotations like `@BeforeClass` and `@AfterClass`. Instead, you would typically use a testing framework such as unittest or pytest to define setup and teardown methods.