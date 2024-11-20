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
