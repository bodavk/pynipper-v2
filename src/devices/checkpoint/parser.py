import re

class CheckPointFileParser:
    """
    Parses nested CheckPoint (*.C, *.fws) configuration files.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> dict:
        with open(self.filepath, 'r') as f:
            content = f.read()
        
        # Tokenize based on parentheses and whitespace
        tokens = re.findall(r'\(|\)|[^\s()]+', content)
        
        return self._build_tree(tokens)

    def _build_tree(self, tokens: list) -> dict:
        """Builds a nested structure using key-value pairs."""
        stack = [{}]
        
        i = 0
        while i < len(tokens):
            token = tokens[i]

            if token == '(':
                # Start new nested dict
                new_dict = {}
                # In CheckPoint, nested structures often follow a key
                # This is a basic assumption, will need refinement.
                stack[-1][f"sub_{len(stack[-1])}"] = new_dict
                stack.append(new_dict)
            elif token == ')':
                # End nested dict
                stack.pop()
            else:
                # Add key/value
                key = f"item_{len(stack[-1])}"
                stack[-1][key] = token
            i += 1
        
        return stack[0]
