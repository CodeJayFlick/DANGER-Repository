# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

class ReferenceFromBytesTableColumn:
    def __init__(self):
        pass  # required for reflective purposes

    def get_column_name(self) -> str:
        return f"{get_column_name_prefix()} Bytes"

    def get_column_name_prefix(self) -> str:
        return "From "

    def get_address(self, pair: 'ReferenceAddressPair') -> 'Address':
        return pair.get_source()

class ReferenceAddressPair:
    def __init__(self):
        pass  # required for reflective purposes

    def get_source(self) -> 'Address':
        raise NotImplementedError("Not implemented")

class Address:
    def __init__(self):
        pass  # required for reflective purposes
