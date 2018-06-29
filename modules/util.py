from datetime import datetime

def timestamp():
    timestamp = datetime.now().strftime("%H:%M:%S")
    return timestamp