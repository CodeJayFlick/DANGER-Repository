from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

# Load the pre-trained language model
MODEL_NAME = "microsoft/DialoGPT-medium"  # You can use other models like gpt-neo
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForCausalLM.from_pretrained(MODEL_NAME)

# Personality Settings
personality_traits = [
    "You are a friendly and humorous chatbot.",
    "You like to joke around but always remain polite.",
    "Your responses are brief but engaging.",
]

def generate_response(personality, user_input, chat_history_ids=None, max_length=1000):
    """
    Generates a chatbot response given personality and user input.
    """
    input_ids = tokenizer.encode(personality + user_input + tokenizer.eos_token, return_tensors="pt")
    
    # Append new user input to the chat history
    if chat_history_ids is not None:
        bot_input_ids = torch.cat([chat_history_ids, input_ids], dim=-1)
    else:
        bot_input_ids = input_ids

    # Generate response
    chat_history_ids = model.generate(
        bot_input_ids,
        max_length=max_length,
        pad_token_id=tokenizer.eos_token_id,
        temperature=0.7,
        top_p=0.9,
        repetition_penalty=1.1,
        do_sample=True
    )

    # Decode and return response
    response = tokenizer.decode(chat_history_ids[:, bot_input_ids.shape[-1]:][0], skip_special_tokens=True)
    return response, chat_history_ids

def main():
    print("Welcome to the AI Chatbot!")
    print("Choose a personality:")
    for i, trait in enumerate(personality_traits, start=1):
        print(f"{i}. {trait}")
    
    try:
        choice = int(input("\nEnter your choice (1-3): ").strip())
        personality = personality_traits[choice - 1]
    except (ValueError, IndexError):
        print("Invalid choice. Defaulting to a friendly personality.")
        personality = personality_traits[0]

    print(f"\nChatbot initialized with personality: {personality}\n")
    print("Type 'exit' to end the conversation.\n")

    chat_history_ids = None  # Track conversation history
    while True:
        user_input = input("You: ").strip()
        if user_input.lower() == "exit":
            print("Chatbot: Goodbye! Have a great day!")
            break

        try:
            response, chat_history_ids = generate_response(personality, user_input, chat_history_ids)
            print(f"Chatbot: {response}")
        except Exception as e:
            print(f"An error occurred: {e}")
            break

if __name__ == "__main__":
    main()
