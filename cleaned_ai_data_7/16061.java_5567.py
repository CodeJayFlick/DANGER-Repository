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

class TfDataType:
    to_tf_map = create_to_tf_map()
    from_tf_map = create_from_tf_map()

    def __init__(self):
        pass

    @staticmethod
    def create_to_tf_map():
        return {
            'float32': 1,
            'float64': 2,
            'int32': 3,
            'int64': 9,
            'uint8': 4,
            'int8': 6,
            'boolean': 10,
            'string': 7
        }

    @staticmethod
    def create_from_tf_map():
        return {
            1: 'float32',
            2: 'float64',
            3: 'int32',
            4: 'uint8',
            6: 'int8',
            7: 'string',
            9: 'int64',
            10: 'boolean'
        }

    @staticmethod
    def to_tf(data_type):
        return TfDataType.to_tf_map.get(data_type)

    @staticmethod
    def from_tf(data_type):
        return TfDataType.from_tf_map.get(data_type)
