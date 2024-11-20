Here is the equivalent Python code:

```Python
class BaseConfigProfile:
    CONFIG_OVERRIDES = {
        "quarkus.jaeger.sampler-type": "const"
    }

    VERSION_STORE_CONFIG = {
        "nessie.version.store.advanced.key-prefix": "nessie-test",
        "nessie.version.store.advanced.commit-retries": 42,
        "nessie.version.store.advanced.tx.batch-size": 41
    }

    def get_config_overrides(self):
        return {**self.CONFIG_OVERRIDES, **self.VERSION_STORE_CONFIG}
```

Note that Python does not have a direct equivalent to Java's `ImmutableMap`. The above code uses regular dictionaries which are mutable. If you want an immutable dictionary-like object in Python, you can use the `frozenset` module from the `dataclasses` library:

```Python
from dataclasses import frozen

@frozen
class BaseConfigProfile:
    CONFIG_OVERRIDES = {
        "quarkus.jaeger.sampler-type": "const"
    }

    VERSION_STORE_CONFIG = {
        "nessie.version.store.advanced.key-prefix": "nessie-test",
        "nessie.version.store.advanced.commit-retries": 42,
        "nessie.version.store.advanced.tx.batch-size": 41
    }

    def get_config_overrides(self):
        return {**self.CONFIG_OVERRIDES, **self.VERSION_STORE_CONFIG}
```