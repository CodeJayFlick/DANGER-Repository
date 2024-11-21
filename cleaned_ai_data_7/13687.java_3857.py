class AbstractDocumentTest:
    KEY = "key"
    VALUE = "value"

    class DocumentImplementation:
        def __init__(self, properties):
            self.properties = properties

        def put(self, key, value):
            self.properties[key] = value

        def get(self, key):
            return self.properties.get(key)

        def children(self, key, implementation=lambda x: None):
            if key in self.properties:
                return [implementation(x) for x in self.properties[key]]
            else:
                return []

    document = AbstractDocumentTest.DocumentImplementation({})

    def test_put_and_get(self):
        self.document.put(AbstractDocumentTest.KEY, AbstractDocumentTest.VALUE)
        assert self.document.get(AbstractDocumentTest.KEY) == AbstractDocumentTest.VALUE

    def test_retrieve_children(self):
        children = [{} for _ in range(2)]
        self.document.put(AbstractDocumentTest.KEY, children)

        child_stream = self.document.children(AbstractDocumentTest.KEY,
                                               lambda x: None)
        assert len(child_stream) == 2

    def test_retrieve_empty_stream_for_non_existing_children(self):
        child_stream = self.document.children(AbstractDocumentTest.KEY,
                                             lambda x: None)
        assert len(child_stream) == 0

    def test_include_props_in_to_string(self):
        props = {AbstractDocumentTest.KEY: AbstractDocumentTest.VALUE}
        document = AbstractDocumentTest.DocumentImplementation(props)

        assert str(document).find(AbstractDocumentTest.KEY) != -1
        assert str(document).find(AbstractDocumentTest.VALUE) != -1


if __name__ == "__main__":
    test_suite = unittest.TestSuite()
    suite = unittest.makeSuite(AbstractDocumentTest, 'test')
    test_suite.addTest(unittest.find_test_cases(suite))
    runner = unittest.TextTestRunner()
    result = runner.run(test_suite)
