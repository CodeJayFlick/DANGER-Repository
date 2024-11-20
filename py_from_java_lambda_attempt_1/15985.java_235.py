Here is the translation of the Java code into Python:

```Python
class PpEngine:
    ENGINE_NAME = "PaddlePaddle"
    RANK = 10

    def __init__(self):
        self.version = JniUtils.get_version()

    @classmethod
    def new_instance(cls):
        LibUtils.load_library()
        return cls()

    def get_alternative_engine(self):
        if not self.initialized and not bool("ai.djl.paddlepaddle.disable_alternative"):
            engine = Engine.instance()
            if engine.rank < self.RANK:
                alternative_engine = engine
            self.initialized = True
        return alternative_engine

    @property
    def get_engine_name(self):
        return self.ENGINE_NAME

    @property
    def get_rank(self):
        return self.RANK

    @property
    def get_version(self):
        return self.version

    def has_capability(self, capability):
        # Default device is always CPU
        return False

    def new_model(self, name, device):
        return PpModel(name, device, NDManager(device))

    def new_symbol_block(self, manager):
        raise NotImplementedError("PaddlePaddle does not support empty SymbolBlock")

    @property
    def get_base_manager(self):
        return self.get_base_manager(None)

    def get_base_manager(self, device=None):
        if device is None:
            return PpNDManager.system_manager().new_sub_manager()
        else:
            return PpNDManager.system_manager().new_sub_manager(device)

    def new_gradient_collector(self):
        raise NotImplementedError("Not supported for PaddlePaddle")

    def set_random_seed(self, seed):
        raise NotImplementedError("Not supported for PaddlePaddle")

    @property
    def __str__(self):
        return f"{self.get_engine_name}:{self.get_version()}"
```

Note: This translation assumes that the Java code is using a JniUtils class to get the version and LibUtils class to load the library. These classes are not present in Python, so you would need to implement them or use alternative methods to achieve similar functionality.

Also note that this translation does not include any imports for modules like `JniUtils`, `LibUtils`, etc., as these are assumed to be implemented elsewhere in your code.