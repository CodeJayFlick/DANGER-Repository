import os

def train_bert():
    try:
        args = ["-g", "1", "-m", "1", "-e", "1"]
        TrainBertOnCode.run_example(args)
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    train_bert()
