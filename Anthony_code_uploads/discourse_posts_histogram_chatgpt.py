import requests
from bs4 import BeautifulSoup
import json
import string
import matplotlib.pyplot as plt
from collections import Counter

thread_url = "https://discuss.python.org/t/about-the-committers-category/19.json"
headers = {"User-Agent": "Mozilla/5.0"}

def extract_posts_from_discourse_thread(url):
    """Extracts raw text from all posts in the Discourse thread, handling pagination."""
    all_posts_text = []
    post_number = 0
    try:
        while True:
            paginated_url = f"{url}?post_number={post_number}"
            response = requests.get(paginated_url, headers=headers)
            if response.status_code == 200:
                try:
                    thread_data = response.json()
                    posts = thread_data['post_stream']['posts']
                    if not posts:  # If there are no more posts, break the loop
                        break
                    for post in posts:
                        post_content = post['cooked']  # 'cooked' contains the HTML of the post content
                        soup = BeautifulSoup(post_content, 'html.parser')
                        text = soup.get_text()  # Extracting plain text from HTML
                        all_posts_text.append(text)
                    post_number += len(posts)  # Move to the next set of posts
                except json.JSONDecodeError as e:
                    print(f"JSON decoding error: {e}")
                    break
            else:
                print(f"Failed to retrieve the thread: {response.status_code}")
                break
    except Exception as e:
        print(f"An error occurred: {e}")

    return " ".join(all_posts_text)  # Combine all posts into one large text

def letter_frequency_histogram(text):
    """Plots a histogram of letter frequencies in the given text."""
    # Filter only alphabetic characters and convert to lowercase
    text = ''.join([char.lower() for char in text if char.isalpha()])
    
    # Count frequency of each letter
    letter_counts = Counter(text)
    
    # Prepare data for the histogram
    letters = list(string.ascii_lowercase)
    frequencies = [letter_counts[letter] for letter in letters]
    
    # Plotting the histogram
    plt.figure(figsize=(10, 6))
    plt.bar(letters, frequencies, color='skyblue')
    plt.title('Letter Frequency Histogram')
    plt.xlabel('Letters')
    plt.ylabel('Frequency')
    plt.show()

# Example usage
posts_text = extract_posts_from_discourse_thread(thread_url)
if posts_text:
    letter_frequency_histogram(posts_text)
