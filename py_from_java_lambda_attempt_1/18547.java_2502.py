Here is the translation of the Java code to Python:
```
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
# with the License. A copy of the License is located at http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

class AlbContext:
    def __init__(self):
        self.target_group_arn = None

    @property
    def target_group_arn(self):
        return self._target_group_arn

    @target_group_arn.setter
    def target_group_arn(self, value):
        self._target_group_arn = value
```
Note that I've used Python's `@property` and `@setter` decorators to implement the getter and setter methods for the `targetGroupArn` attribute. This is equivalent to Java's public getters and setters.