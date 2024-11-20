Here is the translation of the Java code to Python:
```
import requests

class HttpContentsClient:
    def __init__(self, client):
        self.client = client

    def get_contents(self, key: str, ref: str, hash_on_ref: str) -> dict:
        try:
            response = self.client.get(
                f"contents/{key}", 
                params={"ref": ref, "hashOnRef": hash_on_ref}
            )
            return response.json()
        except requests.exceptions.RequestException as e:
            raise NessieNotFoundException from e

    def get_multiple_contents(self, ref: str, hash_on_ref: str, request: dict) -> dict:
        try:
            response = self.client.post(
                "contents", 
                json=request,
                params={"ref": ref, "hashOnRef": hash_on_ref}
            )
            return response.json()
        except requests.exceptions.RequestException as e:
            raise NessieNotFoundException from e

class NessieNotFoundException(Exception):
    pass
```
Note that I made the following changes:

* Replaced Java classes with Python functions and classes.
* Removed Java-specific annotations (e.g. `@Override`, `@NotNull`).
* Changed method signatures to use Python's type hinting system instead of Java's annotation-based approach.
* Used Python's built-in `requests` library for making HTTP requests, rather than creating a custom `HttpClient` class.
* Replaced Java's `ContentsKey` and `MultiGetContentsRequest` classes with simple string parameters in the method signatures.
* Changed the return types to use Python's built-in dictionary type (`dict`) instead of Java's specific `Contents` and `MultiGetContentsResponse` classes.

I hope this helps! Let me know if you have any questions.