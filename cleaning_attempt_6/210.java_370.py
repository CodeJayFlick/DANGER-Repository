from typing import Mapping, Collection, Set

class DebuggerRegisterMapper:
    def get_target_register(self, name: str) -> dict:
        # Your implementation here
        pass

    def get_trace_register(self, name: str) -> dict:
        # Your implementation here
        pass

    def trace_to_target(self, register_value: dict) -> Mapping[str, bytes]:
        if not isinstance(register_value['register'], (str)):
            raise ValueError('Invalid register type')
        
        return {name: value for name, value in zip(['target_register', 'value'], [self.get_trace_register(name), register_value['value']])}

    def trace_to_target(self, collection: Collection[dict]) -> Mapping[str, bytes]:
        result = {}
        for item in collection:
            entry = self.trace_to_target(item)
            if isinstance(entry, dict):
                result.update(entry)

        return result

    def target_to_trace(self, treg_name: str, value: bytes) -> dict:
        # Your implementation here
        pass

    def target_to_trace(self, register: dict, value: bytes) -> dict:
        if not isinstance(register['register'], (str)):
            raise ValueError('Invalid register type')
        
        return {'register': self.target_to_trace(register['name'], value), 'value': value}

    def trace_to_target(self, values: Mapping[str, bytes]) -> Collection[dict]:
        result = []
        for key, value in values.items():
            item = self.target_to_trace(key, value)
            if isinstance(item, dict):
                result.append(item)

        return result

    def target_to_trace(self, treg: str) -> dict:
        # Your implementation here
        pass

    def get_default_type_info(self, lreg: dict) -> dict:
        # Your implementation here
        pass

    def get_registers_on_target(self) -> Set[dict]:
        # Your implementation here
        pass

    def target_register_added(self, register: str):
        # Your implementation here
        pass

    def target_register_removed(self, register: str):
        # Your implementation here
        pass
