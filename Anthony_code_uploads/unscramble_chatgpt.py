import itertools
import nltk
from nltk.corpus import words

# Download the words corpus
nltk.download('words')

def unscramble_word(scrambled_word):
    """
    Unscrambles a word using the nltk words corpus.
    """
    # Get the set of valid English words from nltk
    word_set = set(words.words())

    # Generate all permutations of the scrambled word
    permutations = [''.join(p) for p in itertools.permutations(scrambled_word)]
    
    # Check if any permutation is a valid word in the nltk dictionary
    for word in permutations:
        if word.lower() in word_set:
            return word
    
    # If no valid word found
    return None

# Example usage
scrambled_text = "tset"
unscrambled = unscramble_word(scrambled_text)
if unscrambled:
    print(f"The unscrambled word is: {unscrambled}")
else:
    print("No valid word found.")
