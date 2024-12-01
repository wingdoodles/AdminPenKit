import tkinter as tk
from gui.main_window import MainWindow
from utils.logger import Logger

def main():
    # Initialize logger
    logger = Logger()
    logger.info("Starting AdminPenKit...")
    
    # Create main window
    root = tk.Tk()
    root.title("AdminPenKit")
    
    # Set initial window size
    root.geometry("1200x800")
    
    # Create main application
    app = MainWindow(root)

    
    # Start the application
    logger.info("GUI initialized, starting main loop")
    root.mainloop()

if __name__ == "__main__":
    main()
