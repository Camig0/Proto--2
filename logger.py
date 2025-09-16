import json

def log_to_file(filename, data: dict):
    # edit file
    file = load_json(filename)
    file[f"{len(file)+1}"] = data
    
    #write to file
    with open(filename, 'w', encoding="utf-8") as f:
        json.dump(file, f, indent=2)


def print_log(filename):
    file = load_json(filename)
    for index, data in file.items():
        print(index)
        for key, value in data.items():
            print(f"---> {key}: {value}")

def load_json(filename):
    try:
        with open(filename, 'r', encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"File {filename} not found.")
    except json.JSONDecodeError:
        raise ValueError(f"File {filename} is not a valid JSON file.")
    
def reset_log(filename):
    with open(filename, "w") as f:
        json.dump({}, f)


if __name__ == "__main__":
    log_to_file("message_logs.json", {"A_moves": [
        "U",
        "R",
        "F",
        "D",
        "L",
        "B"
        ],
        "encrypted_message": "asdjaksjneb"})
    reset_log("message_logs.json")
