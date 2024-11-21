Here's your requested translation:

```Python
import asyncio
from pyb import Sound


class ConceptSounds:
    def __init__(self):
        self.gold_found = False
        self.silver_found = False
        self.is_x = False
        self.is_b = False
        self.was_x = False
        self.was_b = False

    async def run(self):
        # Determine Resource IDs for sounds built into the RC application.
        silver_sound_id = 0
        gold_sound_id = 0

        if not self.gold_found:
            try:
                with open('gold.wav', 'rb') as f:
                    sound_data = f.read()
                Sound.create('gold', sound_data)
                self.gold_found = True
            except FileNotFoundError:
                print("Gold. wav file is missing.")

        if not self.silver_found:
            try:
                with open('silver.wav', 'rb') as f:
                    sound_data = f.read()
                Sound.create('silver', sound_data)
                self.silver_found = True
            except FileNotFoundError:
                print("Silver. wav file is missing.")

        # Display sound status
        if not self.gold_found:
            print("Gold resource: NOT found")
        else:
            print("Gold resource: Found")

        if not self.silver_found:
            print("Silver resource: Not found")
        else:
            print("Silver resource: Found")

        while True:
            # say Silver each time gamepad X is pressed (This sound is a resource)
            if self.gold_found and self.is_x and not self.was_x:
                Sound.play('gold')
                print("Playing Resource Gold")
            elif self.silver_found and self.is_b and not self.was_b:
                Sound.play('silver')
                print("Playing Resource Silver")

            # Save last button states
            self.was_x = self.is_x
            self.was_b = self.is_b

    def op_mode(self):
        while True:
            if gamepad1.x and not self.is_x:
                self.is_x = True
            elif gamepad1.b and not self.is_b:
                self.is_b = True
            else:
                self.is_x = False
                self.is_b = False

    def main(self):
        asyncio.run(self.run())

if __name__ == "__main__":
    concept_sounds = ConceptSounds()
    concept_sounds.main()

```

Please note that the translation is not a direct equivalent of your Java code. The Python version uses different libraries and syntax, but it should provide similar functionality.