Here is the translation of the given Java code into Python:

```Python
class BinarySearchFormat:
    VALID_CHARS = "01x?."
    
    def __init__(self):
        self.statusText = ""
        
    def get_tooltip(self):
        return f"Interpret value as a sequence of binary digits.\n" \
               "Spaces will start the next byte.  Bit sequences less\n" \
               "than 8 bits are padded with 0's to the left. \n" \
               "Enter 'x', '.' or '?' for a wildcard bit"

    def get_search_data(self, input):
        tokens = input.split()
        n = len(tokens)
        bytes_ = [0] * n
        mask = [0] * n
        
        index = 0
        while index < n:
            token = tokens[index]
            
            if not self.is_valid_binary(token):
                return {"status": "Invalid Input", "data": None}
                
            byte_val, mask_val = self.get_byte_mask(token)
            bytes_[index] = byte_val
            mask[index] = mask_val
            index += 1
            
        return {"input": input, "bytes": bytes_, "mask": mask}

    def is_valid_binary(self, str):
        if len(str) > 8:
            self.status_text = f"Max group size exceeded. Enter <space> to add more."
            return False
        
        for char in str:
            if VALID_CHARS.find(char) < 0:
                return False
        return True

    def get_byte_mask(self, token):
        byte_val = 0
        mask_val = 0
        
        for i, char in enumerate(token):
            if char == '1':
                byte_val |= 2 ** (7 - i)
                mask_val |= 2 ** (7 - i)

        return byte_val, mask_val

    def uses_endieness(self):
        return False
```

Please note that Python does not have an exact equivalent of Java's `StringTokenizer` class. Instead, we use the built-in string methods like `split()` to split a string into tokens and iterate over them using a for loop or while loop.