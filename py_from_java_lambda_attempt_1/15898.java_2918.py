Here is the translation of the Java code into equivalent Python:

```Python
class XgbEngine:
    ENGINE_NAME = "XGBoost"
    RANK = 10

    def __init__(self):
        pass

    @staticmethod
    def new_instance():
        return XgbEngine()

    def get_alternative_engine(self):
        if not self.initialized and not bool("ai.djl.xgboost.disable_alternative"):
            engine = Engine.get_instance()
            if engine.rank < self.RANK:
                self.alternative_engine = engine
            self.initialized = True
        return self.alternative_engine

    def get_engine_name(self):
        return self.ENGINE_NAME

    def get_rank(self):
        return self.RANK

    def get_version(self):
        return "1.3.1"

    def has_capability(self, capability):
        return False

    def new_symbol_block(self, manager):
        raise UnsupportedOperationException("XGBoost does not support empty symbol block")

    def new_model(self, name, device):
        return XgbModel(name, self.new_base_manager(device))

    def new_base_manager(self):
        return self.new_base_manager(None)

    def new_base_manager(self, device):
        return XgbNDManager.get_system_manager().new_sub_manager(device)

    def new_gradient_collector(self):
        raise UnsupportedOperationException("Not supported for XGBoost")

    def set_random_seed(self, seed):
        raise UnsupportedOperationException("Not supported for XGBoost")

    def __str__(self):
        return f"{self.ENGINE_NAME}:{self.get_version()}"
```

Note that Python does not have direct equivalent of Java's `@Override` annotation. Also, some methods like `JniUtils.checkCall(0);`, which is used to load the native library in Java, are not present in this translation as it seems unrelated to XGBoost engine itself and might be handled separately for each platform.