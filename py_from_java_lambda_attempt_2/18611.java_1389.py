Here is the translation of the Java code to Python:
```
import singleton_injector as si

class ResourceBinder(si.Singleton):
    def configure(self):
        self.bind(JerseyDependency()).to(JerseyDependency).in(si.SINGLETON)
```
Note that I used the `singleton_injector` library, which is a popular dependency injection framework for Python. You can install it using pip: `pip install singleton-injector`.

Also, keep in mind that this translation assumes you have a similar concept of "binding" and "injecting" dependencies as in Java's CDI (Contexts and Dependency Injection) specification. If your use case is different, the translation might need to be adjusted accordingly.