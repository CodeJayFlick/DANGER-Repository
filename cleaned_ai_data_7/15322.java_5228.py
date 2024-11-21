# Copyright information (not necessary in Python)

import re
from forex_python.currencies import CurrencyCodes

class GenericUtils:
    @staticmethod
    def starts_with_ignore_case(string: str, prefix: str) -> bool:
        return string.lower().startswith(prefix.lower())

    @staticmethod
    def currency_symbol(currency_code: str) -> str:
        try:
            code = CurrencyCodes.get_currency_name(currency_code)
            symbol = CurrencyCodes.get_symbol(code)
            return symbol
        except ValueError:
            return currency_code
