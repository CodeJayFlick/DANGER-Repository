# Licensed under Apache License 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

from typing import Collection

class ColumnConstraintProvider:
    """Extension point for introducing ColumnConstraints to the system.
       File names must end with 'ColumnConstraintProvider' in order to be found."""

    def get_column_constraints(self) -> Collection['ColumnConstraint']:
        """Returns a collection of ColumnConstraints that will be used by the table column filtering feature
           to filter tables based on column values.

        :return: A collection of ColumnConstraints to be added as possible column filters.
        """
        pass

class ColumnConstraint:
    pass
