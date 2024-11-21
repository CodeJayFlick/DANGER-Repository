Here is the equivalent Python code:

```Python
from datetime import date, timezone

class DateColumnTypeMapper:
    def convert(self, value: date) -> date:
        return value.astimezone(timezone.utc).date()
```

Note that in this translation, I've made a few assumptions about how you want to handle dates. Specifically, the original code uses `java.time.LocalDate` and `java.time.ZoneId`, which are not directly equivalent to Python's built-in `datetime.date`. However, it seems like what you're trying to do is convert a Java-style date object (`Date`) into a Python-style date object (`date`).