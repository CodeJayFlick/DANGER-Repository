import sys

class JsrTestRun:
    def __init__(self):
        pass

    @staticmethod
    def main(args=None):
        print(JsrTestRun.try_object("test"))
        return None


    @staticmethod
    def try_object(o):
        x = None
        try:
            x = str(o)
        except Exception as e:
            pass
        finally:
            if x is None:
                x = "null"
        return x

if __name__ == "__main__":
    JsrTestRun.main()
