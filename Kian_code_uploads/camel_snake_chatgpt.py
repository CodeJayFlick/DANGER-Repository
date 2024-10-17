import re

def camel_to_snake(word):
    """Convert a single camel case word to snake case."""
    snake_word = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', word)
    snake_word = re.sub('([a-z0-9])([A-Z])', r'\1_\2', snake_word)
    return snake_word.lower()

def convert_file_to_snake_case(input_file, output_file):
    """Convert all camel case words in the input file to snake case and save the result to the output file."""
    with open(input_file, 'r') as file:
        content = file.read()

    # Find all words, convert camel case ones to snake case
    converted_content = re.sub(r'\b[A-Za-z0-9]*[A-Z][a-z0-9]*\b', 
                               lambda match: camel_to_snake(match.group()), content)

    # Write the converted content to the output file
    with open(output_file, 'w') as file:
        file.write(converted_content)

    print(f"File '{input_file}' has been converted to snake case and saved as '{output_file}'.")

# Example usage:
input_file = 'input.txt'  # Replace with your file path
output_file = 'output.txt'  # Replace with the desired output file path
convert_file_to_snake_case(input_file, output_file)
