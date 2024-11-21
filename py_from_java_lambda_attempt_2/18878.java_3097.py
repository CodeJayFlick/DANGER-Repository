Here is your Java code translated into Python:

```Python
import unittest
from parameterized import parameterized

class TestValidation(unittest.TestCase):

    @parameterized.expand([
        {"referenceName": "a", "expected_hash_length": 40},
        {"referenceName": "a_ b-", "expected_hash_length": 40},
        {"referenceName": "a_-c", "expected_hash_length": None},
        {"referenceName": "abc/def", "expected_hash_length": None}
    ])
    def test_valid_ref_names(self, reference_name):
        validate_reference_name(reference_name)
        validate_reference_name_or_hash(reference_name)

    @parameterized.expand([
        {"referenceName": "", "expected_exception_message": f"Invalid reference name: {''}"},
        {"referenceName": "abc/", "expected_exception_message": f"Invalid reference name: {''}" },
        {"referenceName": ".foo", "expected_exception_message": f"Invalid reference name: {.foo}" },
        {"referenceName": "abc/def/../blah", "expected_exception_message": f"Invalid reference name: abc/def/../blah"},
        {"referenceName": "abc/de..blah", "expected_exception_message": f"Invalid reference name: abc/de..blah"},
        {"referenceName": "abc/de@{blah}", "expected_exception_message": f"Invalid reference name: abc/de@{blah}"}
    ])
    def test_invalid_ref_names(self, reference_name):
        with self.assertRaises(IllegalArgumentException) as e:
            validate_reference_name(reference_name)
        self.assertEqual(e.exception.getMessage(), f"{Validation.REF_NAME_MESSAGE} - but was: {reference_name}")

    @parameterized.expand([
        {"hash": "11223344556677889900112233445566778899001122", "expected_exception_message": None},
        {"hash": "abcDEF4242424242424242424242BEEF00DEAD4211223344556677889900", "expected_exception_message": None}
    ])
    def test_valid_hashes(self, hash):
        validate_hash(hash)
        validate_reference_name_or_hash(hash)

    @parameterized.expand([
        {"hash": "", "expected_exception_message": f"Invalid hash: {''}" },
        {"hash": "abc/", "expected_exception_message": f"Invalid hash: abc/" },
        {"hash": ".foo", "expected_exception_message": f"Invalid hash: .foo"},
        {"hash": "abc/def/../blah", "expected_exception_message": f"Invalid hash: abc/def/../blah"},
        {"hash": "abc/de..blah", "expected_exception_message": f"Invalid hash: abc/de..blah"},
        {"hash": "abc/de@{blah}", "expected_exception_message": f"Invalid hash: abc/de@{blah}"}
    ])
    def test_invalid_hashes(self, hash):
        with self.assertRaises(IllegalArgumentException) as e:
            validate_hash(hash)
        self.assertEqual(e.exception.getMessage(), f"{Validation.HASH_MESSAGE} - but was: {hash}")

    @parameterized.expand([
        {"referenceName": "a", "hash": "11223344556677889900112233445566778899001122"},
        {"referenceName": "a_ b-", "hash": "112233445566778899001122abcDEF4242424242424242424242BEEF00DEAD42"}
    ])
    def test_valid_names_and_hashes(self, reference_name, hash):
        Branch.of(reference_name, hash)
        Tag.of(reference_name, hash)

    @parameterized.expand([
        {"referenceName": "a", "hash": "abcDEF4242424242424242424242BEEF00DEADxy"},
        {"referenceName": "a_ b-", "hash": "meep"},
        {"referenceName": "a_-c", "hash": "0"},
        {"referenceName": "abc/def", "hash": "##"}
    ])
    def test_valid_names_and_invalid_hashes(self, reference_name, hash):
        with self.assertRaises(IllegalArgumentException) as e:
            Branch.of(reference_name, hash)
        self.assertEqual(e.exception.getMessage(), f"{Validation.HASH_MESSAGE} - but was: {hash}")

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have a direct equivalent to Java's `@ParameterizedTest` and `@ValueSource`. Instead, we use the `parameterized` library which provides similar functionality.