Here is the equivalent Python code:

```Python
import json
from unittest import TestCase

class CoinGeckoTest(TestCase):
    def test_parse(self):
        with open('coingecko.json', 'r') as f:
            data = json.load(f)
        
        rates = coin_gecko.parse(data)
        self.assertEqual(45, len(rates))

# Assuming you have a separate file for the CoinGecko class
import moshi

class CoinGecko(moshi.Builder):
    def __init__(self, builder):
        super().__init__()
        # Initialize your CoinGecko instance here
```

Please note that Python does not support direct equivalent of Java's `@Test` annotation. Instead, you would write test cases using the built-in unittest module in Python.

Also, this code assumes that there is a separate file for the `CoinGecko` class and its methods are implemented correctly to parse JSON data into `ExchangeRateEntry` objects.