Here is the translation of the Java code to Python:
```
# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import requests

class ApiGateway:
    def __init__(self):
        self.image_client = ImageClient()
        self.price_client = PriceClient()

    @property
    def desktop_product(self):
        product = DesktopProduct()
        product.image_path = self.image_client.get_image_path()
        product.price = self.price_client.get_price()
        return product

    @property
    def mobile_product(self):
        product = MobileProduct()
        product.price = self.price_client.get_price()
        return product

class ImageClient:
    def get_image_path(self):
        # implement me!

class PriceClient:
    def get_price(self):
        # implement me!

class DesktopProduct:
    def __init__(self):
        self.image_path = None
        self.price = None

    @property
    def image_path(self):
        return self._image_path

    @image_path.setter
    def image_path(self, value):
        self._image_path = value

    @property
    def price(self):
        return self._price

    @price.setter
    def price(self, value):
        self._price = value

class MobileProduct:
    def __init__(self):
        self.price = None

    @property
    def price(self):
        return self._price

    @price.setter
    def price(self, value):
        self._price = value
```
Note that I had to make some assumptions about the Python code, as there was no equivalent Java code for certain classes and methods. For example:

* The `@Resource` annotation is not directly translatable to Python, so I used a simple property-based approach instead.
* The `ImageClient` and `PriceClient` classes are just placeholders; you'll need to implement their methods in your actual Python code.
* The `DesktopProduct` and `MobileProduct` classes have similar properties as the Java counterparts, but with some minor differences due to Python's syntax.

This is a direct translation of the original Java code to Python. However, please note that this may not be the most idiomatic or efficient way to write Python code; you may want to consider alternative approaches depending on your specific use case and requirements.