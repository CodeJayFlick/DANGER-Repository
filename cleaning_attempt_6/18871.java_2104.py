class EntriesParams:
    def __init__(self):
        self.max_records = None
        self.page_token = None
        self.query_expression = None
        self.hash_on_ref = None
        self.namespace_depth = 0

def test_builder():
    max_records = 23
    namespace_depth = 0
    hash_value = "1234567890123456"
    page_token = "aabbcc"
    query_expression = "some_expression"

    params = EntriesParams()
    params.max_records = max_records
    params.page_token = page_token
    params.query_expression = query_expression
    params.hash_on_ref = hash_value
    params.namespace_depth = namespace_depth

    assert params.page_token == page_token
    assert params.max_records == max_records
    assert params.namespace_depth == namespace_depth
    assert params.query_expression == query_expression
    assert params.hash_on_ref == hash_value


def test_empty():
    params = EntriesParams()
    
    assert params is not None
    assert params.max_records is None
    assert params.page_token is None
    assert params.query_expression is None
    assert params.namespace_depth == 0
    assert params.hash_on_ref is None

if __name__ == "__main__":
    test_builder()
    test_empty()
