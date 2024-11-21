Here is the translation of the Java code to Python:

```
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions and limitations under the License.

class StandardCapabilities:
    CUDA = "CUDA"
    CUDNN = "CUDNN"
    MKL = "MKL"
    MKLDNN = "MKLDNN"
    OPENMP = "OPENMP"

    def __init__(self):
        pass
```

Note that in Python, we don't need to use the `public` keyword for class members or methods. Also, the constructor (`__init__`) is defined using the same name as the class itself.