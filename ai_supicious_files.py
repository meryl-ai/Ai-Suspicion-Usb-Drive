import os
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# NORMAL USB DATA FOR AI

normal_usb_data = np.array([
    [130, 0, 0],
    [150, 0, 1],
    [120, 0, 0]
])

model = IsolationForest(contamination=0.2, random_state=42)
model.fit(normal_usb_data)


# SYSTEM FILES TO IGNORE

ignore_files = [".DS_Store", "Thumbs.db", "desktop.ini"]


# SCAN USB FILES
def scan_usb(path):
    total_files = 0
    exe_files = 0
    hidden_files = 0
    file_list = []

    for root, dirs, files in os.walk(path):
        for file in files:
            total_files += 1
            if file.lower().endswith(".exe"):
                exe_files += 1
            if file.startswith("."):
                hidden_files += 1
            file_list.append(os.path.join(root, file))
    return [total_files, exe_files, hidden_files], file_list


# AI SUSPICION SCORE

def ai_suspicion_score(features):
    score = -model.decision_function([features])[0]
    return min(100, max(0, score * 100))


# FLAG SUSPICIOUS FILES
def check_file_suspicious(file_path):
    filename = os.path.basename(file_path)
    
    # Ignore common system files
    if filename in ignore_files:
        return False
    
    # Flag exe and hidden files as suspicious
    if filename.lower().endswith(".exe") or filename.startswith("."):
        return True
    
    # Flag unusually large files (>50 MB)
    try:
        if os.path.getsize(file_path) > 50 * 1024 * 1024:
            return True
    except:
        return False
    
    return False


# PROCESS USB

def process_usb(drive_letter):
    print(f"\nScanning USB at {drive_letter}...\n")

    # Get USB features and file list
    features, file_list = scan_usb(drive_letter)
    score = ai_suspicion_score(features)  # original AI score

    # Check suspicious files
    suspicious_files = []
    for f in file_list:
        if check_file_suspicious(f):
            suspicious_files.append(f)

    # Upgrade score if suspicious files exist
    if suspicious_files:
        # Push score higher (e.g., at least 70 if suspicious files exist)
        score = max(score, 70)

    # Print USB features and AI suspicion score
    print("USB Features:")
    print("Total files:", features[0])
    print("Executable files:", features[1])
    print("Hidden files:", features[2])
    print("AI USB Suspicion Score:", round(score, 2), "/ 100\n")

    # Print suspicious file list
    if not suspicious_files and score < 50:
        print("All files are OK. USB suspicion score is normal ✅")
    else:
        for s in suspicious_files:
            print(f"⚠ Suspicious file detected: {s}")
        print(f"\nUSB AI suspicion score: {round(score,2)} / 100")


# WATCHDOG FOR NEW USB
class USBHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            usb_path = event.src_path
            time.sleep(1)  # wait for mount
            process_usb(usb_path)

def monitor_usb(drive_letter="E:\\"):
    # Scan existing USB at start
    if os.path.exists(drive_letter):
        process_usb(drive_letter)

    # Monitor new USBs
    event_handler = USBHandler()
    observer = Observer()
    observer.schedule(event_handler, drive_letter, recursive=False)
    observer.start()
    print(f"\nMonitoring {drive_letter} for USB insertion...\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


# RUN PROGRAM

if __name__ == "__main__":
    monitor_usb("E:\\")  # change to your USB drive letter
