Here is the translation of the Java code to Python:
```
import json

class NessieHttpResponseFilter:
    def __init__(self, mapper):
        self.mapper = mapper

    def filter(self, con):
        try:
            ResponseCheckFilter.check_response(con, self.mapper)
        except Exception as e:
            raise HttpClientException(e)  # pass up invalid response exception as untyped exception
```
Note that I've made the following changes:

* Replaced `package` declaration with nothing (Python doesn't have a package declaration).
* Imported only `json`, which is equivalent to Java's `ObjectMapper`.
* Replaced `public class` with just `class`.
* Removed `private final` and replaced it with no modifier.
* Replaced `@Override` with nothing (Python doesn't have an override annotation).
* Replaced `throw new HttpClientException(e)` with a simple `raise` statement, since Python's exception handling is different from Java's.

Also note that I've assumed the existence of two other classes: `ResponseCheckFilter` and `HttpClientException`, which would need to be implemented separately.