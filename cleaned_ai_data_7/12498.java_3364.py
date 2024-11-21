class ProcessorContextView:
    def __init__(self):
        pass

    def get_base_context_register(self) -> 'Register':
        # TO DO: implement this method
        return None  # or some default value if not implemented

    def get_registers(self) -> list['Register']:
        # TO DO: implement this method
        return []

    def get_register(self, name: str) -> 'Register':
        # TO DO: implement this method
        return None  # or some default value if not implemented

    def get_value(self, register: 'Register', signed: bool) -> int | None:
        # TO DO: implement this method
        return None  # or some default value if not implemented

    def get_register_value(self, register: 'Register') -> dict[str, int]:
        # TO DO: implement this method
        return {}

    def has_value(self, register: 'Register') -> bool:
        # TO DO: implement this method
        return False  # or some default value if not implemented

def dump_context_value(value: dict[str, int], indent: str = '') -> str:
    buf = StringBuilder()
    _dump_context_value(value, indent, buf)
    return buf.toString()

def _dump_context_value(value: dict[str, int], indent: str, buf: StringBuilder):
    if not indent:
        indent = ''
    base_reg = next(k for k in value.keys())
    base_reg_size = 8 * (base_reg['size'] - 1) + base_reg['lsb']
    for reg_name, reg_value in value.items():
        if reg_value != 0:
            buf.append(f"{indent}{reg_name}({value[reg_name]['msb'], value[reg_name]['lsb']}) = {hex(reg_value)}\n")
            _dump_context_value(dict([k: v for k, v in zip(value.keys(), [v['child_values'][i] if i < len(v['child_values']) else None for i, v in enumerate(value.values())])]), indent + '    ', buf)
