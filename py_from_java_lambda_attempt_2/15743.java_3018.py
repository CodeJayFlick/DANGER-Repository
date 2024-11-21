Here's the translation:

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

class Transform:
    """An interface to apply various transforms to the input."""

    def __call__(self, array: 'NDArray') -> 'NDArray':
        """
        Applies the transform to the given NDArray.
        
        :param array: The NDArray on which the transform is applied
        :return: The output of the transform
        """
        raise NotImplementedError("Transform must be implemented")
```

Note that I've used Python's built-in `class` syntax and defined a class called `Transform`. The `__call__` method is used to define how instances of this class should behave when they're called like functions. In this case, the `transform` method takes an instance of some hypothetical `NDArray` class as input and returns another such instance.

The rest of the code is just a bunch of comments that were copied from the original Java file; I didn't translate those to Python because there's no direct equivalent in Python for what they're doing.