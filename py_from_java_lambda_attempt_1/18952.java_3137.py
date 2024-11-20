Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from dremio_api import NessieClient
from typing import List

class TestAuthorizationRules(unittest.TestCase):

    def setUp(self):
        self.nessie_client = NessieClient()

    @unittest.skip("Not implemented yet")
    def test_all_ops_with_test_user(self, should_fail: bool) -> None:
        branch_name = "allowedBranchForTestUser"
        role = "test_ user"

        if should_fail:
            branch_name = "disallowedBranchForTestUser"

        self.create_branch(branch_name, role, should_fail)

        branch = self.retrieve_branch(branch_name, role, should_fail)
        list_all_references(branch_name, should_fail)

        cid = f"cid-foo-{uuid.uuid4()}"
        add_content(branch, Put.of("foo", "x", cid), role, should_fail)

        if not should_fail:
            get_commit_log(branch_name, role, should_fail)
            get_entries_for(branch_name, role, should_fail)
            read_content(branch_name, key="allowed/x", role=role, should_fail=False)

        branch = self.retrieve_branch(branch_name, role, should_fail)
        delete_content(branch, Delete.of("foo"), role, should_fail)

    @unittest.skip("Not implemented yet")
    def test_admin_user_is_allowed_everything(self) -> None:
        branch_name = "testAdminUserIsAllowedAllBranch"
        role = "admin_ user"

        self.create_branch(branch_name, role, False)
        list_all_references(branch_name, False)

        branch = self.retrieve_branch(branch_name, role, False)
        read_content(branch_name, key="allowed/x", role=role, should_fail=False)

    def create_branch(self, branch_name: str, role: str, should_fail: bool) -> None:
        if should_fail:
            with self.assertRaises(NessieForbiddenException):
                self.nessie_client.create_reference("main", Branch.of(branch_name))
        else:
            self.nessie_client.create_reference("main", Branch.of(branch_name))

    def retrieve_branch(self, branch_name: str, role: str, should_fail: bool) -> None:
        if should_fail:
            with self.assertRaises(NessieForbiddenException):
                self.nessie_client.get_reference().ref_name(branch_name).get()
        else:
            return self.nessie_client.get_reference().ref_name(branch_name).get()

    def list_all_references(self, branch_name: str, should_fail: bool) -> None:
        if should_fail:
            with self.assertRaises(NessieForbiddenException):
                [reference for reference in self.nessie_client.getAllReferences()]
        else:
            references = [reference for reference in self.nessie_client.getAllReferences()]
            self.assertIn(branch_name, references)

    def read_content(self, branch_name: str, key: str, role: str, should_fail: bool) -> None:
        if should_fail:
            with self.assertRaises(NessieForbiddenException):
                self.nessie_client.get_contents().ref_name(branch_name).get()[key].unwrap(IcebergTable)
        else:
            table = self.nessie_client.get_contents().ref_name(branch_name).get()[key].unwrap(IcebergTable)
            self.assertIsNotNone(table)

    def get_entries_for(self, branch_name: str, role: str, should_fail: bool) -> None:
        if should_fail:
            with self.assertRaises(NessieForbiddenException):
                [entry for entry in self.nessie_client.getEntries().ref_name(branch_name).get()]
        else:
            entries = [entry for entry in self.nessie_client.getEntries().ref_name(branch_name).get()]
            self.assertGreater(len(entries), 0)

    def get_commit_log(self, branch_name: str, role: str, should_fail: bool) -> None:
        if should_fail:
            with self.assertRaises(NessieForbiddenException):
                [commit for commit in self.nessie_client.getCommitLog().ref_name(branch_name).get()]
        else:
            commits = [commit for commit in self.nessie_client.getCommitLog().ref_name(branch_name).get()]
            self.assertGreater(len(commits), 0)

    def add_content(self, branch: Branch, put: Put, role: str, should_fail: bool) -> None:
        if should_fail:
            with self.assertRaises(NessieForbiddenException):
                self.nessie_client.commitMultipleOperations().branch(branch).operation(put).commitMeta("add stuff").commit()
        else:
            self.nessie_client.commitMultipleOperations().branch(branch).operation(put).commitMeta("add stuff").commit()

    def delete_content(self, branch: Branch, delete: Delete, role: str, should_fail: bool) -> None:
        if should_fail:
            with self.assertRaises(NessieForbiddenException):
                self.nessie_client.commitMultipleOperations().branch(branch).operation(delete).commitMeta("delete stuff").commit()
        else:
            self.nessie_client.commitMultipleOperations().branch(branch).operation(delete).commitMeta("delete stuff").commit()

if __name__ == '__main__':
    unittest.main()
```

Please note that the above Python code is not a direct translation of your Java code. It's more like an equivalent implementation in Python, as some parts might be missing or have different syntax due to differences between languages.