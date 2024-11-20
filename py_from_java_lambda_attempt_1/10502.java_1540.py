Here is the translation of the Java code into Python:

```Python
import re
from typing import List

class HtmlLineSplitter:
    MAX_WORD_LENGTH = 10

    def split(self, text: str, max_line_length: int) -> List[str]:
        return self.split(text, max_line_length, False)

    def split(self, text: str, max_line_length: int, retain_spacing: bool) -> List[str]:
        lines = []
        newlines = text.split('\n')
        
        if max_line_length <= 0:
            lines.extend(newlines)
            return lines
        
        counter = WhitespaceHandler(retain_spacing)

        for line in newlines:
            if len(line) == 0:  # this was a newline character
                lines.append(line)
                continue
            
            sub_lines = self.wrap(line, max_line_length, counter)
            lines.extend(sub_lines)
        
        return lines

    def wrap(self, text: str, max_line_length: int, whitespacer: 'WhitespaceHandler') -> List[str]:
        lines = []
        start = 0
        size = 0
        break_needed = False
        has_forced_break = False
        
        for i in range(len(text)):
            c = text[i]
            if c == '\t':
                size += 4
            else:
                size += 1
            
            hit_max_length = size >= max_line_length
            is_whitespace = re.match(r'\s', str(c))
            
            if break_needed and not is_whitespace:  # we found a whitespace--break!
                line = text[start:i]
                lines.append(line)
                
                i += whitespacer.count_spaces(text, i) - start
                start = i
                size = 0
                break_needed = False
            
            elif hit_max_length:
                if not is_whitespace:  # past hard limit; just chop at the original desired length
                    has_forced_break = True
                    break_needed = False
                    end = start + max_line_length
                    lines.append(text[start:end])
                    start = end
                    size = i - start
                else:
                    line = text[start:i]
                    if not is_whitespace:  # not on a whitespace; look for whitespace to split on
                        end = re.search(r'\s', str(line)).start()
                        if end < 0:
                            break_needed = True
                            continue
                        
                        line = line[:end + 1]  # +1 to include the space; it will get trimmed below as needed
                    lines.append(whitespacer.trim(line))
                    
                    start += len(line)
                    
                    i = max(i, start)  # adjust for removed spaces
                    
                    size = i - start
            
            else:
                if hit_max_length:  # handle any trailing text; don't split if no breaks were forced (this keeps the text consistent--either break all text or break none)
                    line = whitespacer.trim(text[start:])
                    
                    lines.extend(self.force_split_on(line, max_line_length))
        
        return lines

    def force_split_on(self, s: str, size: int) -> List[str]:
        lines = []
        buffy = ''
        for i in range(len(s)):
            buffy += s[i]
            
            if len(buffy) == size:
                lines.append(buffy)
                buffy = ''
        
        if len(buffy) > 0:
            lines.append(buffy)
        
        return lines


class WhitespaceHandler:
    def __init__(self, retain_spacing: bool):
        self.retain_spacing = retain_spacing

    def count_spaces(self, text: str, i: int) -> int:
        if not self.retain_spacing:
            while i < len(text) and re.match(r'\s', str(text[i])):
                i += 1
        return i - start

    def trim(self, line: str) -> str:
        if not self.retain_spacing:
            line = line.strip()
        
        return line


# Usage example:

splitter = HtmlLineSplitter()
text = "This is a test text that needs to be wrapped."
lines = splitter.split(text, 20)
for line in lines:
    print(line)

```

Please note that Python does not support operator overloading like Java.