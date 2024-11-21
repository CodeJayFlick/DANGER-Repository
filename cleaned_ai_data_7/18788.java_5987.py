import requests

class HttpAssignTag:
    def __init__(self, client):
        self.client = client

    def assign_to(self, assign_to: 'Reference') -> 'HttpAssignTag':
        self.assign_to = assign_to
        return self

    def assign(self) -> None:
        try:
            response = self.client.get_tree_api().assign_tag(tag_name=self.tag_name, hash=self.hash, assign_to=assign_to)
            if not 200 <= response.status_code < 300:
                raise Exception(f"Failed to assign tag: {response.text}")
        except requests.exceptions.RequestException as e:
            if isinstance(e, requests.exceptions.HTTPError):
                if e.response.status_code == 404:
                    raise NessieNotFoundException("Tag not found")
                elif e.response.status_code == 409:
                    raise NessieConflictException("Conflict while assigning tag")

class Reference:
    pass

class NessieApiClient:
    def get_tree_api(self) -> 'TreeApi':
        return TreeApi()

class TreeApi:
    def assign_tag(self, tag_name: str, hash: str, assign_to: 'Reference') -> requests.Response:
        # implement this method
        pass

# Example usage:
client = NessieApiClient()
http_assign_tag = HttpAssignTag(client)
reference = Reference()  # assume you have a way to create a Reference object
http_assign_tag.assign_to(reference).assign()
