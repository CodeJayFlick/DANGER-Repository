Here is the equivalent Python code:

```Python
import datetime
from time import strftime

def format_example():
    now = datetime.datetime.now()
    
    print(f"The cow jumped over the moon\n")
    print(f"The cow jumped over the moon {now}\n")
    print(f"The cow jumped over the moon - timestamp: {now.strftime('%c')}\n")

    date_format = "%a, %d %b %Y at %I:%M%p"
    print(f"The cow jumped over the moon at {strftime(date_format)}\n")

    padding = f"{1:03}"
    print(f"Padding: {padding}\n")
    
    hex_value = "0x%x" % 10
    print(f"Hex: {hex_value}\n")
    
    left_justified = f"{1:-10d}"
    right_justified = f"{1:10d}"
    print(f"Left-justified: {left_justified}\n")
    print(f"Right-justified: {right_justified}\n")

    string_fill_left = f"'{('Fill' * 3):<-10s}'"
    string_fill_right = f"'{('Fill' * 3):>10s}'"
    
    print(f"String fill, left justified: {string_fill_left}\n")
    print(f"String fill, right justified: {string_fill_right}\n")

format_example()
```

This Python code is equivalent to the provided Java code. It uses the `datetime` and `time` modules for date and time formatting.