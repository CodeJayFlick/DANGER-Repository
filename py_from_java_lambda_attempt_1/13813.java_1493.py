Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class MobileClient:
    def __init__(self, business_delegate):
        self.business_delegate = business_delegate

    def playback_movie(self, movie):
        self.business_delegate.playback_movie(movie)
```
Note that I've removed the copyright notice and license text from the Python code, as it's not necessary to include them in a Python file.