class FrameBasedGameLoop:
    def __init__(self):
        self.is_game_running = True

    def process_game_loop(self):
        while self.is_game_running:
            self.process_input()
            self.update()
            self.render()

    def process_input(self):
        # Input processing code here
        pass

    def update(self):
        controller.move_bullet(0.5)

    def render(self):
        # Rendering code here
        pass


# Example usage:

game_loop = FrameBasedGameLoop()
while game_loop.is_game_running:
    game_loop.process_input()
    game_loop.update()
    game_loop.render()

