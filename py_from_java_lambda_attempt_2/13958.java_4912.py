Here is a translation of the Java code into equivalent Python:

```Python
import logging

class HibernateUtil:
    _session_factory = None

    def __init__(self):
        self._build_session_factory()

    def _build_session_factory(self):
        try:
            registry = StandardServiceRegistryBuilder().configure()
            metadata_sources = MetadataSources(registry)
            return metadata_sources.build_metadata().buildSessionFactory()
        except Exception as ex:
            logging.error("Initial SessionFactory creation failed.", ex)
            raise

    @property
    def session_factory(self):
        if self._session_factory is None:
            self._build_session_factory()
        return self._session_factory


# Usage example:

hibernate_util = HibernateUtil()

if hibernate_util.session_factory is not None:
    print(hibernate_util.session_factory)
else:
    print("Session factory has not been initialized.")
```

Please note that Python does not have direct equivalent of Java's `@Slf4j` annotation. The logging mechanism in the provided code uses Python's built-in `logging` module.

Also, Python doesn't support static variables like Java does with `private static final`. Instead, we use instance variables and a property to control access to them.