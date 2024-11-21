Here is the translation of the given Java code into equivalent Python:

```Python
import os
from unittest import TestCase
from ghidra_framework_client import GhidraServerHandle
from ghidra_server_remote import ServerInfo
from utilities.util import FileUtilities


class TestGhidraServerSerialFilterFailure(TestCase):

    def setUp(self):
        self.server_root = None

    def tearDown(self):
        if self.server_root is not None:
            try:
                os.remove(self.server_root)
            except FileNotFoundError:
                pass

    def test_serialization_failure(self):
        ServerInfo(server="localhost", port=ServerTestUtil.GHIDRA_TEST_SERVER_PORT)

        server_handle = GhidraServerHandle()
        try:
            server_handle.get_repository_server(get_bogus_user_subject(), [])
            self.fail("serial filter rejection failed to perform")
        except RemoteException as e:
            cause = e.cause
            self.assertTrue(isinstance(cause, UnmarshalException))
            cause = cause.cause
            self.assertTrue(isinstance(cause, InvalidClassException))

    def get_bogus_user_subject(self):
        username = "test"
        pset = set()
        empty_set = set()
        pset.add(BogusPrincipal(username))
        subj = Subject(False, pset, empty_set, empty_set)
        return subj


class BogusPrincipal:
    def __init__(self, username: str):
        self.username = username

    def get_name(self) -> str:
        return self.username
```

Please note that Python does not have direct equivalent of Java's `@Before` and `@After` methods. Instead, you can use the built-in `setUp()` and `tearDown()` methods provided by the unittest module in Python.

Also, Python doesn't support static classes like Java. So I've removed the `static class BogusPrincipal implements Principal, java.io.Serializable { ... }` declaration from your code.