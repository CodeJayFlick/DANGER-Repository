Here is the translation of the Java code to Python:
```
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions and limitations under the License.

class Preconditions:
    def __init__(self):
        pass

    @staticmethod
    def check_argument(expression: bool, error_message: str) -> None:
        if not expression:
            raise ValueError(error_message)
```
Note that I've kept the same method names and parameter types as in the original Java code. In Python, we don't need to declare variables or methods ahead of time like you do in Java, so the `__init__` method is empty since it's just a constructor.

Also, instead of throwing an `IllegalArgumentException`, I threw a `ValueError`. This is because Python doesn't have a direct equivalent to Java's `IllegalStateException`, and `ValueError` seems like a reasonable choice for this specific use case.