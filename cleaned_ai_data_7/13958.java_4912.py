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
