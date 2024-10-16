class NumberToWordsConverter:
    def __init__(self):
        self.units = [
            "", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
            "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen",
            "seventeen", "eighteen", "nineteen"
        ]
        self.tens = [
            "", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"
        ]
        self.thousands = ["", "thousand", "million", "billion", "trillion"]

    def convert(self, number):
        if isinstance(number, float):
            whole_part = int(number)
            decimal_part = int(round((number - whole_part) * 100))  # Convert to cents
            return self.convert(whole_part) + " point " + self.convert(decimal_part)

        if number == 0:
            return "zero"

        if number < 0:
            return "minus " + self.convert(-number)

        words = ""
        for idx, chunk in enumerate(self.split_number(number)):
            if chunk > 0:
                words = self.chunk_to_words(chunk).strip() + " " + self.thousands[idx] + " " + words

        return words.strip()

    def split_number(self, number):
        chunks = []
        while number > 0:
            chunks.append(number % 1000)
            number //= 1000
        return chunks

    def chunk_to_words(self, chunk):
        words = ""
        if chunk >= 100:
            words += self.units[chunk // 100] + " hundred "
            chunk %= 100

        if chunk >= 20:
            words += self.tens[chunk // 10] + " "
            chunk %= 10

        if chunk > 0:
            words += self.units[chunk] + " "

        return words.strip()

    def convert_currency(self, amount, currency='dollars'):
        if amount < 0:
            return "minus " + self.convert_currency(-amount, currency)

        whole_part = int(amount)
        decimal_part = int(round((amount - whole_part) * 100))

        words = self.convert(whole_part) + " " + currency
        if decimal_part > 0:
            words += " and " + self.convert(decimal_part) + " cents"

        return words.strip()


def main():
    converter = NumberToWordsConverter()

    while True:
        user_input = input("Enter a number (or type 'exit' to quit): ")

        if user_input.lower() == 'exit':
            break

        try:
            if '.' in user_input:
                number = float(user_input)
            else:
                number = int(user_input)

            if number < -999999999 or number > 999999999:
                print("Please enter a number between -999,999,999 and 999,999,999.")
                continue

            words = converter.convert(number)
            print(f"The number {number} in words is: {words}")
        except ValueError:
            print("Invalid input. Please enter a valid integer or float.")

        # Currency Conversion
        currency_input = input("Do you want to convert it to currency? (yes/no): ")
        if currency_input.lower() == 'yes':
            currency = input("Enter the currency (e.g., dollars, euros): ")
            currency_words = converter.convert_currency(number, currency)
            print(f"The amount in words is: {currency_words}")


if __name__ == "__main__":
    main()