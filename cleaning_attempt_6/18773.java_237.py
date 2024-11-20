import http.client as client

class NessieApiClient:
    def __init__(self, config: 'HttpConfigApi', tree: 'HttpTreeApi', contents: 'HttpContentsApi'):
        self.config = config
        self.tree = tree
        self.contents = contents

    @property
    def tree_api(self):
        return self.tree

    @property
    def contents_api(self):
        return self.contents

    @property
    def config_api(self):
        return self.config

    def close(self):
        pass  # equivalent to Java's `@Override public void close() {}`
