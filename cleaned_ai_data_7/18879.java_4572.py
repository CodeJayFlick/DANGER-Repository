# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc

class AccessChecker:
    def can_view_reference(self, context: 'AccessContext', ref: str) -> None:
        pass

    def can_create_reference(self, context: 'AccessContext', ref: str) -> None:
        pass

    def can_assign_ref_to_hash(self, context: 'AccessContext', ref: str) -> None:
        pass

    def can_delete_reference(self, context: 'AccessContext', ref: str) -> None:
        pass

    def can_read_entries(self, context: 'AccessContext', ref: str) -> None:
        pass

    def can_list_commit_log(self, context: 'AccessContext', ref: str) -> None:
        pass

    def can_commit_change_against_reference(self, context: 'AccessContext', ref: str) -> None:
        pass

    def can_read_entity_value(
            self,
            context: 'AccessContext',
            ref: str,
            key: 'ContentsKey',
            contents_id: str
    ) -> None:
        pass

    def can_update_entity(
            self,
            context: 'AccessContext',
            ref: str,
            key: 'ContentsKey',
            contents_id: str
    ) -> None:
        pass

    def can_delete_entity(
            self,
            context: 'AccessContext',
            ref: str,
            key: 'ContentsKey',
            contents_id: str
    ) -> None:
        pass


class AccessCheckerExtension:
    ACCESS_CHECKER = AccessChecker()

    @abc.abstractmethod
    def after_beans_discovered(self, abd):
        abd.addBean().addType(AccessChecker).addQualifier(Default.Literal.INSTANCE).scope(ApplicationScoped()).produce_with(lambda: self.ACCESS_CHECKER)


# Define the classes used in the code

class ApplicationScoped:
    pass


class Default:
    Literal = object()


class ContentsKey:
    pass


class NamedRef:
    pass
