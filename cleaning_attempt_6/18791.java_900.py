import requests

class NessieApiClient:
    def __init__(self):
        pass  # assume initialization happens elsewhere

class HttpDeleteBranch:
    def __init__(self, client: NessieApiClient):
        self.client = client

    def delete(self) -> None:
        try:
            response = self.client.get_tree_api().delete_branch(branch_name, hash)
            if not response.ok:
                raise Exception(f"Error deleting branch {branch_name}: {response.text}")
        except requests.exceptions.RequestException as e:
            if e.response.status_code == 409:  # Conflict
                raise NessieConflictException(e) from None
            elif e.response.status_code == 404:  # Not Found
                raise NessieNotFoundException(e) from None

class DeleteBranchBuilder:
    pass  # assume this class has methods for building the delete request

class BaseHttpOnBranchRequest(DeleteBranchBuilder):
    def __init__(self, client: NessieApiClient):
        self.client = client

# Usage example:
client = NessieApiClient()
http_delete_branch = HttpDeleteBranch(client)
try:
    http_delete_branch.delete()
except (NessieConflictException, NessieNotFoundException) as e:
    print(f"Error deleting branch: {e}")
