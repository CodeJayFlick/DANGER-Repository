Here is the translation of the given Java code into Python:

```Python
import re

class Formats:
    PATTERN_WHITESPACE = re.compile(r'\s+')
    PATTERN_MONETARY_SPANNABLE = re.compile(
        r'(?:([A-Z]+)\\s?+)?'  # prefix
        + r'([+\-]' + Constants.CURRENCY_PLUS_SIGN + Constants.CURRENCY_MINUS_SIGN +
        r'?+(?:\d*\.?\d{0,2}|\d+))'  # significant
        + r'(\d+)?')  # insignificant

    PATTERN_GROUP_PREFIX = 1  # optional
    PATTERN_GROUP_SIGNIFICANT = 2  # mandatory
    PATTERN_GROUP_INSIGNIFICANT = 3  # optional

    PATTERN_MEMO = re.compile(
        r'(?:Payment request for Coinbase order code: (.+)|Payment request for BitPay invoice (.+) for merchant (.+))', 
        flags=re.IGNORECASE)

    def sanitize_memo(memo):
        if memo is None:
            return None
        m = Formats.PATTERN_MEMO.match(memo)
        if m and m.group(1) is not None:
            return [m.group(1) + ' (via Coinbase)']
        elif m and m.group(2) is not None:
            return [m.group(2) + ' (via BitPay)', m.group(3)]
        else:
            return [memo]
```

Please note that I have used the `re` module for regular expressions in Python. Also, since there's no equivalent to Java's `@Nullable`, I've replaced it with a simple check if the variable is None or not.