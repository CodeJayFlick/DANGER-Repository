Here's a translation of the Java code into equivalent Python:

```Python
import asyncio
from typing import Any

class DbgModelInJvmDebuggerModelFactory:
    def __init__(self):
        pass

    async def build(self) -> Any:
        from dbgmodel.model.impl import DbgModel2Impl  # Assuming this is a module name and class name in your Python code
        model = DbgModel2Impl()
        return await model.start_dbg_eng([])

    def is_compatible(self):
        os_name = os.environ.get('os.name', '').lower()
        return 'windows' in os_name

# You can use this factory to create a debugger object:
factory = DbgModelInJvmDebuggerModelFactory()
model = asyncio.run(factory.build())
```

Please note that the above Python code is just an equivalent translation of your Java code. It may not be exactly what you want, as it depends on how you have structured your project and modules in Python.

Here are some key differences between Java and Python:

1. In Python, we don't need to explicitly define a class for every object or function like we do in Java.
2. The `@Override` annotation is not needed in Python because there's no concept of method overriding as such (Python uses duck typing instead).
3. Python doesn't have built-in support for concurrent programming using the `CompletableFuture` class, so I've used the `asyncio.run()` function to run an asynchronous operation.
4. The Java code has a `FactoryDescription` annotation that's not directly equivalent in Python because it provides metadata about the factory (like its name and description). In Python, you might use docstrings or other forms of documentation for this purpose.

Remember that these are just rough translations; actual implementation details may vary depending on your specific requirements.