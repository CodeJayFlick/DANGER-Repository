Here is the translation of the Java code to Python:

```Python
import threading
from datetime import datetime

class Result:
    def __init__(self):
        self.date_list = []
        self.exception_list = []

def date_format_callable(date_value, in_date_format):
    result = Result()

    for _ in range(5):
        try:
            dt = datetime.strptime(date_value, in_date_format)
            result.date_list.append(dt)
        except Exception as e:
            result.exception_list.append(f"{type(e).__name__}: {e}")

    return result

# Example usage
result = date_format_callable("21/06/2016", "%d/%m/%Y")
print(result.date_list)  # prints the parsed dates
print(result.exception_list)  # prints any exceptions that occurred during parsing
```

Note: The `@Slf4j` annotation is not directly translatable to Python, as it's a Java-specific feature. In this translation, I've removed it and instead used regular print statements for logging purposes.