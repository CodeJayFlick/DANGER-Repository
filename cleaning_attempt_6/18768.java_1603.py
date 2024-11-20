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
