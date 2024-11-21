class SingleLoaderFilter:
    def __init__(self, single: type, loader_args=None):
        self.single = single
        self.loader_args = loader_args if isinstance(loader_args, list) else None

    @property
    def loader_args(self):
        return self.loader_args

    def test(self, loader):
        return isinstance(loader.__class__, self.single)
