import os
import json
from datetime import datetime

def log_to_file(path, data: dict, name=None):
    # If path is a directory, create a new file named with today's date
    if os.path.isdir(path):
        today = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = os.path.join(path, f"{today}.json")
        if name:
            path = os.path.join(path[:-5] + f"_{name}.json")  # insert name before .json
    
    # Ensure directory exists (for both cases)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    # edit file
    file = load_json(path, create_if_missing=True)
    file[f"{len(file)+1}"] = data

    # write to file
    with open(path, 'w', encoding="utf-8") as f:
        json.dump(file, f, indent=2)


def print_log(filename):
    file = load_json(filename)
    for index, data in file.items():
        print(index)
        for key, value in data.items():
            print(f"---> {key}: {value}")


def load_json(filename, create_if_missing=False):
    try:
        with open(filename, 'r', encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        if create_if_missing:
            return {}  # start with an empty log if file doesn't exist
        raise FileNotFoundError(f"File {filename} not found.")
    except json.JSONDecodeError:
        raise ValueError(f"File {filename} is not a valid JSON file.")


def reset_log(filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump({}, f)


if __name__ == "__main__":
    # Works with a specific file
    log_to_file("message_logs.json", {
        "A_moves": ["U", "R", "F", "D", "L", "B"],
        "encrypted_message": "asdjaksjneb"
    })

    # Works with a directory (creates logs/YYYY-MM-DD.json)
    log_to_file("logs", {
        "A_moves": ["U", "R"],
        "encrypted_message": "test123"
    }, name="test_run")

    reset_log("message_logs.json")
