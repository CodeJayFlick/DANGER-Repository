import requests

class HttpCreateReference:
    def __init__(self, client):
        self.client = client
        self.reference = None
        self.source_ref_name = None

    def source_ref_name(self, source_ref_name):
        self.source_ref_name = source_ref_name
        return self

    def reference(self, reference):
        self.reference = reference
        return self

    def create(self) -> dict:
        try:
            response = self.client.get_tree_api().create_reference(
                self.source_ref_name,
                self.reference
            )
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                raise NessieNotFoundException("Reference not found")
            elif e.response.status_code == 409:
                raise NessieConflictException("Conflict while creating reference")

class NessieNotFoundException(Exception):
    pass

class NessieConflictException(Exception):
    pass
