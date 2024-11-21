from typing import Dict, List
import json

class Contents:
    pass

class MultiGetContentsResponse:
    def __init__(self):
        self.contents: List[Dict] = []

def get_contents(key: str, ref: str = None, hash_on_ref: str = None) -> Contents:
    # Your implementation here
    return Contents()

def get_multiple_contents(ref: str = None, hash_on_ref: str = None, request: MultiGetContentsRequest):
    # Your implementation here
    response = MultiGetContentsResponse()
    for key in request.keys:
        contents = get_contents(key)
        if contents is not None:
            response.contents.append(contents.to_dict())
    return response

class NessieNotFoundException(Exception):
    pass

# Example usage:

request = {
    "keys": ["key1", "key2"]
}

response = get_multiple_contents(ref="ref", hash_on_ref=None, request=request)
print(json.dumps(response.__dict__, indent=4))
