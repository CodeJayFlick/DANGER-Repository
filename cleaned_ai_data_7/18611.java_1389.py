import singleton_injector as si

class ResourceBinder(si.Singleton):
    def configure(self):
        self.bind(JerseyDependency()).to(JerseyDependency).in(si.SINGLETON)
