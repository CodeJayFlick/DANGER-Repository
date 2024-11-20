class BertToken:
    def __init__(self, tokens: list[str], token_type: list[int], attention_mask: list[int], valid_length: int):
        self.tokens = tokens
        self.token_type = token_type
        self.attention_mask = attention_mask
        self.valid_length = valid_length

    @property
    def get_tokens(self) -> list[str]:
        return self.tokens

    @property
    def get_token_types(self) -> list[int]:
        return self.token_type

    @property
    def get_attention_mask(self) -> list[int]:
        return self.attention_mask

    @property
    def get_valid_length(self) -> int:
        return self.valid_length


# Example usage:

tokens = ["This", "is", "an", "example"]
token_types = [0, 0, 1, 1]
attention_masks = [1, 1, 1, 1]
valid_length = len(tokens)

bert_token = BertToken(tokens, token_types, attention_masks, valid_length)
print(bert_token.get_tokens)  # Output: ['This', 'is', 'an', 'example']
print(bert_token.get_token_types)  # Output: [0, 0, 1, 1]
print(bert_token.get_attention_mask)  # Output: [1, 1, 1, 1]
print(bert_token.get_valid_length)  # Output: 4
