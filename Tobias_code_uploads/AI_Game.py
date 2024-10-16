import random

# Define a list of questions and answers
questions = [
    {"question": "What is the capital of France?", "answer": "Paris"},
    {"question": "What is 5 + 7?", "answer": "12"},
    {"question": "What is the largest planet in our solar system?", "answer": "Jupiter"},
    {"question": "What is the chemical symbol for water?", "answer": "H2O"},
    {"question": "Who wrote 'To Kill a Mockingbird'?", "answer": "Harper Lee"},
    {"question": "What is the square root of 64?", "answer": "8"},
    {"question": "Who painted the Mona Lisa?", "answer": "Leonardo da Vinci"},
    {"question": "What year did World War II end?", "answer": "1945"},
    {"question": "Which element has the atomic number 1?", "answer": "Hydrogen"},
    {"question": "How many continents are there on Earth?", "answer": "7"}
]

def quiz_user(questions):
    score = 0
    random.shuffle(questions)  # Shuffle the questions

    for i, question_data in enumerate(questions):
        question = question_data["question"]
        correct_answer = question_data["answer"]

        print(f"Question {i + 1}: {question}")
        user_answer = input("Your answer: ")

        if user_answer.strip().lower() == correct_answer.strip().lower():
            print("Correct!\n")
            score += 1
        else:
            print(f"Incorrect! The correct answer is: {correct_answer}\n")

    print(f"Quiz over! You scored {score} out of {len(questions)}.")

# Start the quiz
quiz_user(questions)
