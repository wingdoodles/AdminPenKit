import tkinter as tk
from gui.main_window import MainWindow
from utils.logger import Logger
from utils.error_handler import handle_errors
from utils.performance import measure_performance
from utils.platform_check import PlatformChecker

@handle_errors
@measure_performance
def main():
    # Initialize logger
    logger = Logger()
    logger.info("Starting AdminPenKit...")
    
    # Check platform compatibility
    compatibility = PlatformChecker.check_compatibility()
    if not compatibility['compatible']:
        raise SystemError("Incompatible system")
    
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
