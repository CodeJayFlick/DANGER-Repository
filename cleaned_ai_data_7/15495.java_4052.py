import json

class QaServingTranslator:
    def __init__(self, translator):
        self.translator = translator

    def get_batchifier(self):
        return self.translator.get_batchifier()

    def prepare(self, ctx):
        self.translator.prepare(ctx)

    def process_input(self, ctx, input):
        content = input['content']
        qa = None
        if 'question' in content and 'paragraph' in content:
            question = content['question']
            paragraph = content['paragraph']
            qa = {'question': question, 'paragraph': paragraph}
        else:
            try:
                qa = json.loads(input['data'])  # Assuming input['data'] is a JSON string
            except Exception as e:
                print(f"Error: {e}")
        return self.translator.process_input(ctx, qa)

    def process_output(self, ctx, output):
        ret = self.translator.process_output(ctx, output)
        return {'output': [ret]}

# Example usage:

class QAInput:
    def __init__(self, question, paragraph):
        self.question = question
        self.paragraph = paragraph

def translate(input_data):
    translator = QaServingTranslator(Your_Translator_Instance)  # Replace with your actual translator instance
    ctx = TranslatorContext()  # Assuming you have a TranslatorContext class defined elsewhere in the codebase.
    output = translator.process_input(ctx, input_data)
    return translator.process_output(ctx, output)

# Example usage:
input_data = {
    'content': {'question': 'What is AI?', 'paragraph': 'Artificial intelligence (AI)'},
    'data': '{"question": "What is AI?", "paragraph": "Artificial intelligence (AI)" }'
}
output = translate(input_data)
print(output)

