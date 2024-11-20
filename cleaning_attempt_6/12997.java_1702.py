import os
from antlr4 import *
from collections import defaultdict

class SleighEchoRun:
    def main(self):
        try:
            writer = LineArrayListWriter()
            env = ParsingEnvironment(writer)
            sp = SleighPreprocessor(HashMapPreprocessorDefinitionsAdapter(), args[0])
            sp.process(writer)

            input_stream = ANTLRStringStream(writer.toString())
            lexer = SleighLexer(input_stream)
            lexer.set_env(env)
            tokens = UnbufferedTokenStream(lexer)
            parser = SleighParser(tokens)
            parser.set_env(env)
            parser.set_lexer(lexer)
            root = parser.spec()
            nodes = BufferedTreeNodeStream(root.tree)
            nodes.set_token_stream(tokens)

            walker = SleighEcho(nodes)
            walker.root()

        except Exception as e:
            print(e)


if __name__ == "__main__":
    args = sys.argv[1:]
    run = SleighEchoRun()
    run.main()
