import ijson
import json
import sys
import os

def separate_test_results(input_file_path):
    """
    Streams a large single JSON file and separates the results of
    five major test categories into individual JSON files.
    """
    # 1. Initialize dictionaries to hold aggregated results
    # We will aggregate all 354k results for each test type into a list.
    all_authentication_results = []
    all_avalanche_results = []
    all_bug_test_results = []
    all_statistical_results = []
    all_critical_results = []

    # 2. Define the major test keys (from your function structure)
    test_keys = {
        "authentication_results": all_authentication_results,
        "avalanche_results": all_avalanche_results,
        "bug_test_results": all_bug_test_results,
        "statistical_randomness_results": all_statistical_results,
        "critical_test_results": all_critical_results
    }
    
    print(f"Starting stream parsing of {input_file_path}...")
    
    try:
        # The 'ijson.items' generator will yield each top-level key's value.
        # Since your file is structured {"1": {...}, "2": {...}, ...},
        # the prefix '' (empty string) tells ijson to yield the values 
        # of the keys "1", "2", etc.
        with open(input_file_path, 'r', encoding='utf-8') as f:
            
            # The ijson parser yields (key, value) where key is the record ID (e.g., "1")
            for record_id, record_data in ijson.items(f, ''):
                
                # Iterate through the expected test result keys
                for key, result_list in test_keys.items():
                    # Extract the results for the current test from the record
                    test_result = record_data.get(key)
                    
                    if test_result is not None:
                        # Append the extracted result to its master list
                        # Note: We include the original record ID for tracing
                        result_list.append({
                            "record_id": record_id,
                            "data": test_result
                        })

                # Simple progress indicator
                if int(record_id) % 50000 == 0:
                    sys.stdout.write(f"\rProcessed {record_id} records...")
                    sys.stdout.flush()

    except Exception as e:
        print(f"\n--- ERROR DURING STREAMING ---")
        print(f"An error occurred: {e}")
        print("This often means the JSON structure is slightly different than expected.")
        return

    print(f"\nSuccessfully processed {len(all_authentication_results)} total records.")

    # 3. Write aggregated lists to separate output files
    output_dir = "separated_test_results"
    os.makedirs(output_dir, exist_ok=True)
    
    for key, result_list in test_keys.items():
        output_file = os.path.join(output_dir, f"{key}.json")
        print(f"Writing {len(result_list)} results to {output_file}...")
        
        with open(output_file, 'w', encoding='utf-8') as out_f:
            # Use json.dump for efficient writing of the list
            json.dump(result_list, out_f, indent=2)

    print("\n--- Separation Complete! ---")
    print(f"Files saved in the '{output_dir}' directory.")


# --- RUN THE SCRIPT ---
file_name = "test results/2025-12-13_17-37-30.json"
separate_test_results(file_name)