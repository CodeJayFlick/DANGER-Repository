Here is the translation of the Java code to Python:
```
class MatchAddressRangeFilter:
    def get_association(self, match: 'VTMatch') -> 'VTAssociation':
        return match.get_association()
```
Note that I've kept the type hints for `match` and `association`, as they are useful in Python. However, if you want to remove them, the code would be simply:
```
class MatchAddressRangeFilter:
    def get_association(self, match):
        return match.get_association()
```