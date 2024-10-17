def number_to_words(n: int) -> str:
    if n == 0:
        return "Zero"

    # Define words for numbers
    units = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"]
    teens = ["Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen"]
    tens = ["", "Ten", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"]
    thousands = ["", "Thousand", "Million", "Billion"]

    def wordify(num):
        if num < 10:
            return units[num]
        elif 10 < num < 20:
            return teens[num - 11]
        elif num < 100:
            return tens[num // 10] + ('' if num % 10 == 0 else ' ' + units[num % 10])
        elif num < 1000:
            return units[num // 100] + " Hundred" + ('' if num % 100 == 0 else ' ' + wordify(num % 100))

    def process_chunk(num):
        chunk_word = ''
        for i, group in enumerate(thousands):
            chunk = num % 1000
            if chunk > 0:
                chunk_word = wordify(chunk) + (' ' + group if group else '') + (' ' if chunk_word else '') + chunk_word
            num //= 1000
        return chunk_word

    return process_chunk(n).strip()


# Example usage:
number = 123
print(number_to_words(number))  # Output: One Hundred Twenty Three
