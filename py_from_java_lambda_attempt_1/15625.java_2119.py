Here is the translation of the Java code to Python:

```Python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at:
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions
# and limitations under the License.

class DefaultZooProvider:
    def get_model_zoo(self):
        return DefaultModelZoo()

class ModelZoo:
    pass

class DefaultModelZoo(ModelZoo):
    pass
```

Please note that Python does not have direct equivalent of Java's `package` statement. Also, the concept of interfaces and inheritance is different in Python compared to Java. In this translation, I've kept the same class structure as the original code for simplicity.