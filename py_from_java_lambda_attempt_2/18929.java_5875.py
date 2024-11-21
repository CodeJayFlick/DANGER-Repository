Here is the translation of the Java code into equivalent Python:

```Python
import requests
from unittest import TestCase
from jsonschema.exceptions import ValidationError


class TestNessieError(TestCase):

    base_uri = "http://localhost:19121/api/v1/nessieErrorTest"

    @classmethod
    def setUpClass(cls):
        cls.client = requests.Session()
        mapper = ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).disable( SerializationFeature.FAIL_ON_EMPTY_BEANS)
        cls.client.set_base_url(base_uri)

    def test_null_parameter_query_get(self):
        with self.assertRaises(requests.exceptions.HTTPError) as e:
            response = self.client.get(f"{self.base_uri}/nullParameterQueryGet")
        self.assertEqual(e.response.status_code, 400)
        self.assertEqual(response.json()["message"], "Bad Request (HTTP/400): nullParameterQueryGet.hash: must not be null")

    def test_null_parameter_query_post(self):
        with self.assertRaises(requests.exceptions.HTTPError) as e:
            response = self.client.post(f"{self.base_uri}/nullParameterQueryPost", json={})
        self.assertEqual(e.response.status_code, 400)
        self.assertEqual(response.json()["message"], "Bad Request (HTTP/400): nullParameterQueryPost.hash: must not be null")

    def test_empty_parameter_query_get(self):
        with self.assertRaises(requests.exceptions.HTTPError) as e:
            response = self.client.get(f"{self.base_uri}/emptyParameterQueryGet")
        self.assertEqual(e.response.status_code, 400)
        self.assertEqual(response.json()["message"], "Bad Request (HTTP/400): emptyParameterQueryGet.hash: must not be empty")

    def test_blank_parameter_query_get(self):
        with self.assertRaises(requests.exceptions.HTTPError) as e:
            response = self.client.get(f"{self.base_uri}/blankParameterQueryGet")
        self.assertEqual(e.response.status_code, 400)
        self.assertEqual(response.json()["message"], "Bad Request (HTTP/400): blankParameterQueryGet.hash: must not be blank")

    def test_entity_value_violation(self):
        with self.assertRaises(requests.exceptions.HTTPError) as e:
            response = self.client.put(f"{self.base_uri}/basicEntity", json={"value": None})
        self.assertEqual(e.response.status_code, 400)
        self.assertRegex(response.json()["message"], "basicEntity.entity.value: must not be null")

    def test_broken_entity_serialization(self):
        with self.assertRaises(requests.exceptions.HTTPError) as e:
            response = self.client.put(f"{self.base_uri}/basicEntity", json={"value": 1.234})
        self.assertEqual(e.response.status_code, 400)
        self.assertRegex(response.json()["message"], "basicEntity.entity.value: must be greater than or equal to 3")

    def test_nessie_not_found_exception(self):
        with self.assertRaises(requests.exceptions.HTTPError) as e:
            response = self.client.get(f"{self.base_uri}/nessieNotFound")
        self.assertEqual(e.response.status_code, 404)
        self.assertEqual(response.json()["message"], "not-there-message")

    def test_non_constraint_validation_exceptions(self):
        for path in ["constraintDefinitionException", "constraintDeclarationException", "groupDefinitionException"]:
            with self.assertRaises(requests.exceptions.HTTPError) as e:
                response = self.client.get(f"{self.base_uri}/{path}")
            self.assertEqual(e.response.status_code, 500)
            self.assertRegex(response.json()["message"], f"Internal Server Error (HTTP/500): javax.validation.{path}: meep")

    def test_unhandled_runtime_exception_in_store(self):
        with self.assertRaises(requests.exceptions.HTTPError) as e:
            response = self.client.get(f"{self.base_uri}/unhandledExceptionInTvsStore/runtime")
        self.assertEqual(e.response.status_code, 500)
        self.assertRegex(response.json()["message"], "Internal Server Error (HTTP/500): java.lang.RuntimeException: Store.getValues-throwing")

    def test_backend_throttled_exception_in_store(self):
        with self.assertRaises(requests.exceptions.HTTPError) as e:
            response = self.client.get(f"{self.base_uri}/unhandledExceptionInTvsStore/throttle")
        self.assertEqual(e.response.status_code, 429)
        self.assertRegex(response.json()["message"], "Too Many Requests (HTTP/429): Backend store refused to process the request: org.projectnessie.versioned.BackendLimitExceededException: Store.getValues-throttled")

    def unwrap(self):
        pass
```

Please note that this Python code is not exactly equivalent to the Java code. The `unwrap` method in the original Java code seems to be handling exceptions, but it's unclear what its purpose is or how it should behave in Python.