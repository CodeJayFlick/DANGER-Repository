Here is the translation of the given Java code into equivalent Python:

```Python
# This class tests a demangler that is derived from MDMang using tests 
# codified in MDMangBaseTest (note that new versions of "truth" might need to be added 
# to MDMang for any new, desired demangler output). In this case, this class is testing MDMangVS2013 demangler.
class MDMangVS2013Test:
    def __init__(self):
        self.test_configuration = MDVS2013TestConfiguration(be_quiet())

def be_quiet():
    # This function should return a boolean indicating whether to be quiet or not
    pass

# Define the test configuration class for this demangler.
class MDVS2013TestConfiguration:
    def __init__(self, be_quiet):
        self.be_quiet = be_quiet
```

Please note that Python does not have direct equivalent of Java's `public`, `extends` and other keywords. Also, Python uses indentation to define the scope of a block instead of curly braces like in Java.