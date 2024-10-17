from collections import Counter
import re

# Function to count words in a file
def count_words_in_file(file_path):
    # Read the file content
    with open(file_path, 'r') as file:
        text = file.read()

    # Convert text to lower case and use regex to find words
    words = re.findall(r'\b\w+\b', text.lower())

    # Count the occurrences of each word
    word_counts = Counter(words)

    return word_counts

# Example usage
file_path = 'text.txt'  # Replace with the path to your file
word_counts = count_words_in_file(file_path)

# Print the word counts
for word, count in sorted(word_counts.items()):
    print(f'{word}: {count}')

