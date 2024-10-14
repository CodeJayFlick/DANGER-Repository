town_keywords = [
    "investigate", "village", "trust", "help", "innocent", 
    "protect", "unite", "vote", "lynch", "sheriff", 
    "doctor", "town", "roles", "info", "claim"
]

mafia_keywords = [
    "kill", "murder", "fake", "blame", "suspicious", 
    "lie", "vote me", "deceive", "mafia", "power", 
    "target", "eliminate", "hiding", "scum", "alibi"
]

def classify_post(post):
    post = post.lower()
    town_score = sum(post.count(keyword) for keyword in town_keywords)
    mafia_score = sum(post.count(keyword) for keyword in mafia_keywords)

    if town_score > mafia_score:
        return "Town"
    elif mafia_score > town_score:
        return "Mafia"
    else:
        return "Undetermined"

# Example usage
if __name__ == "__main__":
    post = input("Enter the Mafia post: ")
    result = classify_post(post)
    print(f"The post is classified as: {result}")