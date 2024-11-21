import collections
from typing import Dict, List

class DbgListSymbolsCommand:
    def __init__(self, manager: object, process: object, module: object):
        self.manager = manager
        self.process = process
        self.module = module
        self.symbol_entries = {}

    def complete(self) -> Dict[str, dict]:
        symbol_map = {}
        for entry in self.symbol_entries.values():
            min_symbol = {
                'symbol_index': entry['symbol_id'].symbol_index,
                'type_id': entry['type_id'],
                'name': entry['name'],
                'offset': entry['offset'],
                'size': entry['size'],
                'tag': entry['tag'],
                'module_base': entry['module_base']
            }
            symbol_map[entry['symbol_id'].toString()] = min_symbol
        return symbol_map

    def invoke(self):
        system_objects = self.manager.get_system_objects()
        system_objects.set_current_process_id(self.process.id)
        symbols = self.manager.get_symbols()

        for symbol in symbols.iterate_symbol_matches(self.module.name + '!*'):
            symbol_ids_by_name = symbols.get_symbol_ids_by_name(symbol.name)
            for symbol_id in symbol_ids_by_name:
                symbol_entry = symbols.get_symbol_entry(symbol_id)
                self.symbol_entries[symbol_id] = symbol_entry
