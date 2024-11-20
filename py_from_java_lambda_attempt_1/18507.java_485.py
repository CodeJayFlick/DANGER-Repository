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

class InvalidRequestEventException(Exception):
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if cause is not None:
            super().__init__(message, cause)
        else:
            super().__init__(message)

# End of file
```
Note that I've kept the copyright notice and license information at the top, as they are an integral part of the code. The rest of the translation involves converting Java classes to Python classes (using `class` instead of `public class`) and methods (`__init__` instead of a constructor).