import tkinter as tk
from tkinter import filedialog, messagebox
import pygame
from tkinter import ttk
import os

class MusicPlayer:
    def __init__(self, master):
        self.master = master
        self.master.title("Enhanced Music Player")
        self.master.geometry("400x300")

        # Initialize pygame mixer
        pygame.mixer.init()

        # Create UI elements
        self.track_label = tk.Label(master, text="No track loaded", font=("Helvetica", 12))
        self.track_label.pack(pady=10)

        self.play_button = tk.Button(master, text="Play", command=self.play_music)
        self.play_button.pack(pady=5)

        self.pause_button = tk.Button(master, text="Pause", command=self.pause_music)
        self.pause_button.pack(pady=5)

        self.stop_button = tk.Button(master, text="Stop", command=self.stop_music)
        self.stop_button.pack(pady=5)

        self.load_button = tk.Button(master, text="Load", command=self.load_music)
        self.load_button.pack(pady=5)

        # Volume Control
        self.volume_label = tk.Label(master, text="Volume")
        self.volume_label.pack(pady=5)

        self.volume_slider = tk.Scale(master, from_=0, to=1, resolution=0.1, orient=tk.HORIZONTAL, command=self.set_volume)
        self.volume_slider.set(0.5)  # Default volume
        self.volume_slider.pack(pady=5)

        # Track Progress Bar
        self.progress = ttk.Progressbar(master, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=10)

        self.is_paused = False
        self.current_song = None

    def load_music(self):
        # Load music file
        self.current_song = filedialog.askopenfilename(title="Select a Music File",
                                                        filetypes=(("MP3 Files", "*.mp3"), ("WAV Files", "*.wav")))
        if self.current_song:
            pygame.mixer.music.load(self.current_song)
            self.track_label.config(text=os.path.basename(self.current_song))
            print(f"Loaded: {self.current_song}")

    def play_music(self):
        if self.current_song:
            if self.is_paused:
                pygame.mixer.music.unpause()
                self.is_paused = False
            else:
                pygame.mixer.music.play()
                print(f"Playing: {self.current_song}")
                self.update_progress()

    def pause_music(self):
        if self.current_song and not self.is_paused:
            pygame.mixer.music.pause()
            self.is_paused = True
            print("Paused")

    def stop_music(self):
        if self.current_song:
            pygame.mixer.music.stop()
            self.is_paused = False
            self.track_label.config(text="No track loaded")
            print("Stopped")

    def set_volume(self, value):
        volume = float(value)
        pygame.mixer.music.set_volume(volume)
        print(f"Volume set to: {volume}")

    def update_progress(self):
        if self.current_song and pygame.mixer.music.get_busy():
            current_position = pygame.mixer.music.get_pos() / 1000  # get_pos returns milliseconds
            self.progress['value'] = (current_position / self.get_track_length()) * 100
            self.master.after(1000, self.update_progress)  # Update progress every second

    def get_track_length(self):
        if self.current_song:
            # For simplicity, we assume tracks are about 180 seconds long (for demo purposes).
            return 180  # You can implement a proper method to get track length

if __name__ == "__main__":
    root = tk.Tk()
    music_player = MusicPlayer(root)
    root.mainloop()