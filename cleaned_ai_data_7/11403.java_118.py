class AssemblyParseAcceptResult:
    def __init__(self, tree):
        self.tree = tree

    @property
    def isError(self):
        return False

    @property
    def get_tree(self):
        return self.tree

    def __str__(self):
        baos = io.BytesIO()
        print(tree, file=baos)
        return baos.getvalue().decode('utf-8')
