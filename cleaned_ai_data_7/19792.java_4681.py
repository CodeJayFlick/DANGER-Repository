class Namespace:
    class Origin:
        JAVA = "JAVA"
        SCRIPT = "SCRIPT"

    class Key:
        def __init__(self, origin: str, name: str):
            self.origin = origin
            self.name = name

        def get_origin(self) -> str:
            return self.origin

        def get_name(self) -> str:
            return self.name

        def __hash__(self) -> int:
            prime = 31
            result = 1
            result = prime * result + hash(self.name)
            result = prime * result + hash(self.origin)
            return result

        def __eq__(self, other):
            if self is other:
                return True
            if not isinstance(other, Namespace.Key):
                return False
            if self.name != other.name:
                return False
            if self.origin != other.origin:
                return False
            return True

    def __init__(self):
        self.signatures = {}
        self.functions = {}

    def get_signature(self, name: str) -> dict or None:
        return self.signatures.get(name)

    def add_signature(self, sign: dict):
        if self.signatures.get(sign["name"]):
            raise ValueError("function name already used")
        self.signatures[sign["name"]] = sign

    def get_signatures(self) -> list:
        return list(self.signatures.values())

    def get_function(self, name: str) -> dict or None:
        return self.functions.get(name)

    def add_function(self, func: dict):
        if not self.signatures.get(func["name"]):
            raise ValueError("missing signature for function")
        self.functions[func["name"]] = func

    def get_functions(self) -> list:
        return list(self.functions.values())
