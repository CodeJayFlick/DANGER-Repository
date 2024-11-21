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
