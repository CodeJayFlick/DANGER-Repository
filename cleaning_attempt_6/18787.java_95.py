import requests

class HttpAssignBranch:
    def __init__(self, client):
        self.client = client

    def assign_to(self, assign_to: str) -> 'HttpAssignBranch':
        self.assign_to = assign_to
        return self

    def assign(self) -> None:
        try:
            response = self.client.get_tree_api().assign_branch(
                branch_name=self.branch_name,
                hash=self.hash,
                assign_to=assign_to)
            if not response.ok:
                raise requests.exceptions.RequestException(response.text)
        except Exception as e:
            if isinstance(e, requests.exceptions.RequestException):
                raise NessieConflictException("Failed to assign branch") from e
            elif isinstance(e, requests.exceptions.RequestException):
                raise NessieNotFoundException("Branch not found")
