import unittest
from projectnessie.client import NessieApiV1
from projectnessie.model import Branch, CommitMeta, ContentsKey, Entry, IcebergTable, Delete, Put
from http.client import HTTPConnection


class AbstractTestBasicOperations(unittest.TestCase):

    def setUp(self):
        self.api = None

    def tearDown(self):
        if self.api is not None:
            try:
                self.api.close()
            except Exception as e:
                print(f"Error closing Nessie API: {e}")
            finally:
                self.api = None


    def get_catalog(self, branch_name):
        self.api = NessieApiV1(
            base_url="http://localhost:19121/api/v1",
            http_client=HTTPConnection()
        )
        if branch_name is not None:
            self.api.create_reference(branch_name)


    def try_endpoint_pass(self, executable_runnable):
        try:
            executable_runnable()
        except Exception as e:
            raise AssertionError(f"Error executing the endpoint: {e}")


    @unittest.skipIf(not hasattr(unittest.TestCase, 'assertRaises'), "This test requires Python 3.4 or later")
    def test_admin(self):
        self.get_catalog("testx")
        branch = self.api.get_reference().ref_name("testx").get()
        tables = self.api.get_entries().ref_name("testx").get().entries
        self.assertTrue(tables == [])
        key = ContentsKey.of("x", "x")
        try_endpoint_pass(
            lambda: 
                self.api.commit_multiple_operations() \
                    .branch(branch) \
                    .operation(Put.of(key, IcebergTable.of("foo", "x", "cid-foo"))) \
                    .commit_meta(CommitMeta.from_message("empty message")) \
                    .commit()
        )
        self.assertTrue(
            self.api.get_contents().ref_name("testx").key(key).get() is not None
        )
        master = self.api.get_reference().ref_name("testx").get()
        test = Branch.of("testy", master.hash)
        try_endpoint_pass(lambda: 
            self.api.create_reference(master.name, test)
        )
        test2 = self.api.get_reference().ref_name("testy").get()
        try_endpoint_pass(lambda: 
            self.api.delete_branch(test2).delete()
        )
        try_endpoint_pass(
            lambda:
                self.api.commit_multiple_operations() \
                    .branch(master) \
                    .operation(Delete.of(key)) \
                    .commit_meta(CommitMeta.from_message("")) \
                    .commit()
        )
        self.assertTrue(self.api.get_contents().ref_name("testx").key(key).get() == [])
        try_endpoint_pass(
            lambda:
                branch = self.api.get_reference().ref_name(branch.name).get()
                # Note: the initial version-store implementations just committed this operation, but it
                # should actually fail, because the operations of the 1st commit above and this commit
                # have conflicts.
                self.api.commit_multiple_operations() \
                    .branch(branch) \
                    .operation(Put.of(key, IcebergTable.of("bar", "x", "cid-bar"))) \
                    .commit_meta(CommitMeta.from_message("")) \
                    .commit()
        )


    @unittest.skipIf(not hasattr(unittest.TestCase, 'assertRaises'), "This test requires Python 3.4 or later")
    def test_user_cleanup(self):
        self.get_catalog(None)
        r = self.api.get_reference().ref_name("testx").get()
        try_endpoint_pass(
            lambda: 
                self.api.delete_branch(r).delete()
        )


if __name__ == '__main__':
    unittest.main()

