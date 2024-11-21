import unittest
from typing import Callable

class BaseClientAuthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.api = None
        self.customizer = None

    def tearDown(self) -> None:
        if self.api is not None:
            self.api.close()
            self.api = None

    def with_client_customizer(self, customizer: Callable[[dict], dict]) -> None:
        self.customizer = customizer

    def api(self) -> 'NessieApiV1':
        if self.api is not None:
            return self.api

        builder = {'uri': 'http://localhost:19121/api/v1'}
        if self.customizer is not None:
            self.customizer(builder)

        from NessieApiV1 import NessieApiV1
        self.api = NessieApiV1(**builder)
        return self.api
