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
