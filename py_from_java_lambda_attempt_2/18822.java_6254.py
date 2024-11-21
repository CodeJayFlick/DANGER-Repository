Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from typing import List, Optional

class MockPaginatedResponse:
    def __init__(self, more: bool, token: str, elements: List[str]):
        self.more = more
        self.token = token
        self.elements = elements

    def get_elements(self) -> List[str]:
        return self.elements


def test_result_stream_paginator(unittest.TestCase):
    class ResultStreamPaginator:
        @staticmethod
        def generate_stream(ref: str, optional_int: Optional[int]) -> Iterator[MockPaginatedResponse]:
            if ref == "ref":
                raise NessieReferenceNotFoundException("Ref not found")
            elif ref == "ref" and optional_int is None:
                return iter([MockPaginatedResponse(False, None, ["1", "2", "3"])])

        @staticmethod
        def generate_stream(ref: str, optional_int: Optional[int]) -> Iterator[MockPaginatedResponse]:
            if ref == "ref":
                raise NessieReferenceNotFoundException("Ref not found")
            elif ref == "ref" and optional_int is None:
                return iter([MockPaginatedResponse(True, null, ["1", "2", "3"]), MockPaginatedResponse(False, null, ["4", "5", "6"])])

        @staticmethod
        def generate_stream(ref: str, optional_int: Optional[int]) -> Iterator[MockPaginatedResponse]:
            if ref == "ref":
                raise NessieReferenceNotFoundException("Ref not found")
            elif ref == "ref" and optional_int is 5:
                return iter([MockPaginatedResponse(False, None, ["1", "2", "3"])])

        @staticmethod
        def generate_stream(ref: str, optional_int: Optional[int]) -> Iterator[MockPaginatedResponse]:
            if ref == "ref":
                raise NessieReferenceNotFoundException("Ref not found")
            elif ref == "ref" and optional_int is 5:
                return iter([MockPaginatedResponse(True, null, ["1", "2", "3"]), MockPaginatedResponse(False, None, ["4", "5", "6"])])

        @staticmethod
        def generate_stream(ref: str, optional_int: Optional[int]) -> Iterator[MockPaginatedResponse]:
            if ref == "ref":
                raise NessieReferenceNotFoundException("Ref not found")
            elif ref == "ref" and optional_int is None:
                return iter([MockPaginatedResponse(False, null, [])])

        @staticmethod
        def generate_stream(ref: str, optional_int: Optional[int]) -> Iterator[MockPaginatedResponse]:
            if ref == "ref":
                raise NessieReferenceNotFoundException("Ref not found")
            elif ref == "ref" and optional_int is 5:
                return iter([MockPaginatedResponse(True, null, ["1", "2", "3"]), MockPaginatedResponse(False, None, [])])

        @staticmethod
        def generate_stream(ref: str, optional_int: Optional[int]) -> Iterator[MockPaginatedResponse]:
            if ref == "ref":
                raise NessieReferenceNotFoundException("Ref not found")
            elif ref == "ref" and optional_int is 5:
                return iter([MockPaginatedResponse(True, null, ["1", "2", "3"]), MockPaginatedResponse(False, None, [])])

    class Test(unittest.TestCase):
        def test_not_found_exception(self):
            try:
                ResultStreamPaginator.generate_stream("ref", Optional.empty())
            except NessieReferenceNotFoundException as e:
                self.assertEqual(str(e), "Ref not found")

        def test_no_page_size_hint_1_page(self):
            result = list(ResultStreamPaginator.generate_stream("ref", Optional.empty()))
            self.assertListEqual(result, ["1", "2", "3"])

        def test_no_page_size_hint_2_pages(self):
            result = list(ResultStreamPaginator.generate_stream("ref", Optional.empty()))
            self.assertListEqual(result, ["1", "2", "3", "4", "5", "6"])

        def test_page_size_hint_1_page(self):
            result = list(ResultStreamPaginator.generate_stream("ref", 5))
            self.assertListEqual(result, ["1", "2", "3"])

        def test_page_size_hint_2_pages(self):
            result = list(ResultStreamPaginator.generate_stream("ref", 5))
            self.assertListEqual(result, ["1", "2", "3", "4", "5", "6"])

        def test_empty_result(self):
            result = list(ResultStreamPaginator.generate_stream("ref", Optional.empty()))
            self.assertEqual(len(result), 0)

        def test_empty_result_in_page(self):
            result = list(ResultStreamPaginator.generate_stream("ref", 5))
            self.assertListEqual(result, ["1", "2", "3"])

        def test_empty_result_but_more_in_page(self):
            try:
                result = list(ResultStreamPaginator.generate_stream("ref", 5).collect(list))
            except Exception as e:
                self.assertEqual(str(e), "Backend returned empty page, but indicates there are more results")

    unittest.main()
```

Please note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, you would typically define test methods within your class and use the name of those methods as the names for the tests in your testing framework (e.g., `unittest`).