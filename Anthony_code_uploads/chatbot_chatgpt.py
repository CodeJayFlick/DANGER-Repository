import random

class ComplexChatbot:
    def __init__(self):
        self.greetings = ["hello", "hi", "greetings", "sup", "what's up"]
        self.farewells = ["bye", "goodbye", "see you", "exit", "quit"]
        self.topics = ["weather", "news", "jokes", "facts", "games"]
        self.current_topic = None
        self.user_name = None
        self.conversation_log = []
        self.jokes = [
            "Why don't scientists trust atoms? Because they make up everything!",
            "Did you hear about the mathematician who's afraid of negative numbers? He will stop at nothing to avoid them!",
            "Why do we tell actors to 'break a leg'? Because every play has a cast!"
        ]
        self.facts = [
            "Honey never spoils.",
            "Bananas are berries, but strawberries aren't.",
            "A group of flamingos is called a 'flamboyance'."
        ]
        self.questions = {
            "how are you": [
                "I'm just a computer program, but thanks for asking!",
                "Doing well, how about you?",
                "I'm functioning within normal parameters."
            ],
            "what is your name": [
                "I'm a complex chatbot created to have a conversation!",
                "You can call me Chatbot."
            ],
            "what can you do": [
                "I can chat with you, tell jokes, share facts, and more!",
                "I'm here to answer your queries and entertain you!"
            ],
            "tell me about yourself": [
                "I'm a chatbot designed to assist you with various topics!",
                "I love chatting and sharing information."
            ],
            "your name": [
                "My name is Chatbot. It's nice to chat with you!",
                "I go by Chatbot. What's yours?"
            ]
        }

    def greet(self):
        return "Hello! How can I assist you today?"

    def set_user_name(self, name):
        self.user_name = name
        return f"Nice to meet you, {self.user_name}!"

    def log_conversation(self, user_input, bot_response):
        self.conversation_log.append({"user": user_input, "bot": bot_response})

    def get_joke(self):
        return random.choice(self.jokes)

    def get_fact(self):
        return random.choice(self.facts)

    def change_topic(self, topic):
        if topic in self.topics:
            self.current_topic = topic
            return f"Topic changed to {self.current_topic}. What would you like to know about {self.current_topic}?"
        else:
            return f"I'm not familiar with the topic '{topic}'. Please choose from {', '.join(self.topics)}."

    def respond(self, user_input):
        user_input = user_input.lower()
        
        if user_input in self.greetings:
            response = "Hello! How can I assist you today?"
        elif user_input in self.farewells:
            response = "Goodbye! Have a great day!"
        elif "my name is" in user_input:
            name = user_input.split("my name is")[-1].strip()
            response = self.set_user_name(name)
        elif self.user_name and "your name" in user_input:
            response = f"My name is Chatbot, and it's nice to chat with you, {self.user_name}!"
        elif "tell me a joke" in user_input:
            response = self.get_joke()
        elif "tell me a fact" in user_input:
            response = self.get_fact()
        elif "change topic to" in user_input:
            topic = user_input.split("change topic to")[-1].strip()
            response = self.change_topic(topic)
        elif self.current_topic and self.current_topic in user_input:
            response = f"You're currently discussing {self.current_topic}. What else would you like to know?"
        else:
            for question, answers in self.questions.items():
                if question in user_input:
                    response = random.choice(answers)
                    break
            else:
                response = "I'm sorry, I don't understand that. Can you ask something else?"
        
        self.log_conversation(user_input, response)
        return response

    def chat(self):
        print(self.greet())
        while True:
            user_input = input("You: ")
            if user_input.lower() in self.farewells:
                print("Chatbot:", self.respond(user_input))
                break
            response = self.respond(user_input)
            print("Chatbot:", response)

    def review_conversation(self):
        print("\n--- Conversation Log ---")
        for entry in self.conversation_log:
            print(f"You: {entry['user']}")
            print(f"Chatbot: {entry['bot']}")
        print("-----------------------\n")


if __name__ == "__main__":
    chatbot = ComplexChatbot()
    chatbot.chat()
    chatbot.review_conversation()
