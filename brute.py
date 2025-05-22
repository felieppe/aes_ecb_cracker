import os
import time
from collections import deque
import string
from itertools import product
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import multiprocessing
import argparse

# --- Configuration and Known Data ---
# These will now be set by command-line arguments
CLEAR_TEXT = ""
TARGET_CIPHER_BASE64 = ""

# Pre-encode plaintext globally to avoid repeated encoding in workers
CLEAR_TEXT_ENCODED = b"" # Will be updated after parsing args
# Define AES block size globally
AES_BLOCK_SIZE = AES.block_size

# All ASCII characters (0-127)
CHARSET = [chr(i) for i in range(128)]

# Maximum key length to test in BRUTE FORCE mode (default value)
DEFAULT_MAX_LEN_BRUTE_FORCE = 6
# Maximum key length to consider in DICTIONARY mode (longer keys will be truncated)
MAX_LEN_DICT_MODE = 16

UPDATE_INTERVAL = 1.0
PROGRESS_FILE = "bruteforce_progress.txt"

# --- Utility Functions ---
def clear_screen():
    """
    Clears the console screen.
    Works on both Windows ('cls') and Unix/Linux/macOS systems ('clear').
    """
    os.system('cls' if os.name == 'nt' else 'clear')

def save_progress(key):
    """
    Saves the last tested key to a file to allow resumption.
    """
    try:
        with open(PROGRESS_FILE, 'w') as f:
            f.write(key)
    except IOError as e:
        print(f"Error saving progress: {e}")

def load_progress():
    """
    Loads the last tested key from a file to resume the search.
    Returns the key if it exists, otherwise None.
    """
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE, 'r') as f:
                key = f.read().strip()
                if key:
                    print(f"Resuming from key: '{key}'")
                    return key
        except IOError as e:
            print(f"Error loading progress: {e}")
        except Exception as e:
            print(f"Unexpected error reading progress file: {e}")
    return None

def clean_progress_file():
    """
    Deletes the progress file if it exists.
    Called when the search finishes (key found or search space exhausted).
    """
    if os.path.exists(PROGRESS_FILE):
        try:
            os.remove(PROGRESS_FILE)
            print(f"Progress file '{PROGRESS_FILE}' deleted.")
        except OSError as e:
            print(f"Error deleting progress file: {e}")

def format_elapsed_time(seconds):
    """
    Formatea el tiempo transcurrido de segundos a formato H:MM:SS.
    """
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    remaining_seconds = int(seconds % 60)
    return f"{hours:02}:{minutes:02}:{remaining_seconds:02}"

def count_total_brute_force_keys(charset, max_len):
    """
    Calculates the total number of possible keys for brute-force mode.
    """
    total = 0
    len_charset = len(charset)
    for length in range(1, max_len + 1):
        total += (len_charset ** length)
    return total

def count_lines_in_file(filepath):
    """
    Counts the number of lines in a file efficiently.
    """
    count = 0
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in f:
                count += 1
    except FileNotFoundError:
        print(f"\nError: The dictionary file '{filepath}' was not found.")
        exit(1)
    except Exception as e:
        print(f"\nError reading dictionary file '{filepath}': {e}")
        exit(1)
    return count

def display_stats(attempts, speed, recent_keys_with_cipher, elapsed_time_seconds, total_possible_keys, is_resuming=False, start_key_resume=None, use_dict_mode=False, dict_file=None, current_max_len_brute_force=None, final_display=False):
    """
    Displays brute-force statistics in an attractive console format.
    If final_display is True, it does not clear the screen.
    recent_keys_with_cipher is a deque of tuples: (key_string, generated_cipher_base64_string).
    """
    if not final_display:
        clear_screen()

    percentage_complete = (attempts / total_possible_keys) * 100 if total_possible_keys > 0 else 0

    # Calculate estimated time remaining
    estimated_time_remaining_seconds = 0
    if speed > 0 and total_possible_keys > 0:
        keys_remaining = total_possible_keys - attempts
        if keys_remaining > 0:
            estimated_time_remaining_seconds = keys_remaining / speed

    print("==================================================")
    print("           🔑 REAL-TIME AES KEY CRACKER 🔑")
    print("==================================================")
    print(f"\n   Known Data:")
    print(f"     - Plaintext: '{globals()['CLEAR_TEXT']}'") # Access global variable
    print(f"     - Target Ciphertext (Base64): '{globals()['TARGET_CIPHER_BASE64']}'") # Access global variable
    print(f"\n   Search Parameters:")
    print(f"     - Alphabet: ASCII (0-127)")
    if use_dict_mode:
        print(f"     - Mode: Dictionary ('{dict_file}')")
        print(f"     - Max Key Length (truncated): {MAX_LEN_DICT_MODE}")
    else:
        print("     - Mode: Brute Force")
        print(f"     - Max Key Length: {current_max_len_brute_force}")
        # This condition ensures start_key_resume is only used if it's not None and resuming
        if is_resuming and start_key_resume:
            print(f"     - Resuming from: '{start_key_resume}'")
    print("\n--------------------------------------------------")
    print(f"   📈 CURRENT STATISTICS:")
    print(f"     - Key Attempts: {attempts:,}")
    print(f"     - Total Possible Keys: {total_possible_keys:,}")
    print(f"     - Progress: {percentage_complete:.2f}%")
    print(f"     - Speed: {speed:,.2f} keys/sec")
    print(f"     - Time Elapsed: {format_elapsed_time(elapsed_time_seconds)}")
    if estimated_time_remaining_seconds > 0:
        # Corrected function call here
        print(f"     - Estimated Time Remaining: {format_elapsed_time(estimated_time_remaining_seconds)}")
    else:
        print("     - Estimated Time Remaining: N/A")
    print("\n--------------------------------------------------")
    print("   🔍 Last 10 Keys Tested (Key -> Generated Cipher):")
    if recent_keys_with_cipher:
        for i, (key, cipher) in enumerate(recent_keys_with_cipher):
            # Truncate cipher for display if it's too long
            display_cipher = cipher if len(cipher) <= 30 else cipher[:27] + "..."
            print(f"     {i+1}. '{key}' -> '{display_cipher}'")
    else:
        print("     (No keys tested yet)")
    print("--------------------------------------------------")
    if not final_display:
        print("\n   Searching for key... Press Ctrl+C to stop.")
    print("==================================================")

# --- Key Generator ---
def generate_all_keys(charset, max_len, start_key=None):
    """
    Generator that produces all possible base keys up to max_len.
    If start_key is provided, resumes generation from that key.
    """
    found_start = False
    if start_key is None:
        found_start = True

    for length in range(1, max_len + 1):
        for base_key_tuple in product(charset, repeat=length):
            current_key = ''.join(base_key_tuple)
            if not found_start:
                if current_key == start_key:
                    found_start = True
                continue

            yield current_key

def read_keys_from_dict(filepath, max_len_truncate):
    """
    Generator that reads keys from a dictionary file (one key per line).
    Keys are truncated to max_len_truncate.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                key = line.strip()
                if key:
                    yield key[:max_len_truncate]
    except FileNotFoundError:
        print(f"\nError: The dictionary file '{filepath}' was not found.")
        exit(1)
    except Exception as e:
        print(f"\nError reading dictionary file '{filepath}': {e}")
        exit(1)

# --- Global variables for worker processes (initialized by _worker_init) ---
_target_cipher_base64_worker = None
_clear_text_encoded_worker = None
_aes_block_size_worker = None

def _worker_init(target_cipher, clear_text_encoded, aes_block_size):
    """
    Initializer function for multiprocessing pool workers.
    Sets up process-local global variables for each worker.
    """
    global _target_cipher_base64_worker
    global _clear_text_encoded_worker
    global _aes_block_size_worker
    _target_cipher_base64_worker = target_cipher
    _clear_text_encoded_worker = clear_text_encoded
    _aes_block_size_worker = aes_block_size


# --- Worker Function for Multiprocessing ---
def worker_decrypt(base_str_bytes):
    """
    Worker function for the process pool.
    Attempts to decrypt with a given base key.
    Returns a tuple (tested_key_string, generated_cipher_base64_string, found_key_or_None).
    base_str_bytes is the base key as bytes.
    """
    tested_key_str = base_str_bytes.decode()
    generated_cipher_base64 = None
    try:
        # Ensure the key is 16 bytes.
        # If base_str_bytes is shorter, it is padded with nulls.
        full_key = base_str_bytes.ljust(16, b'\x00')

        cipher = AES.new(full_key, AES.MODE_ECB)
        # Use process-local global variables
        ct = cipher.encrypt(pad(_clear_text_encoded_worker, _aes_block_size_worker))
        generated_cipher_base64 = base64.b64encode(ct).decode()

        # Strip any leading/trailing whitespace from both strings before comparison
        if generated_cipher_base64.strip() == _target_cipher_base64_worker.strip():
            return (tested_key_str, generated_cipher_base64, tested_key_str) # Key found
        return (tested_key_str, generated_cipher_base64, None) # Key not found
    except ValueError as e:
        # Catches specific AES errors (e.g., incorrect key length)
        return (tested_key_str, generated_cipher_base64, None)
    except Exception as e:
        # Catches any other unexpected exception during decryption
        return (tested_key_str, generated_cipher_base64, None)


# --- Main Brute-Force Logic ---
def test_keys():
    """
    Performs brute-force or dictionary attack to find the AES key.
    Updates on-screen statistics in real-time and allows progress resumption.
    """
    parser = argparse.ArgumentParser(description="AES brute-force/dictionary tool.")
    parser.add_argument('--text', type=str, required=True, help="The clear text to be used for encryption.")
    parser.add_argument('--target', type=str, required=True, help="The target ciphertext (Base64) to match.")
    parser.add_argument('--dict', type=str, help="Path to the key dictionary file.")
    parser.add_argument('--length', type=int, default=DEFAULT_MAX_LEN_BRUTE_FORCE,
                        help=f"Maximum key length for brute-force mode (default: {DEFAULT_MAX_LEN_BRUTE_FORCE}).")
    args = parser.parse_args()

    # Set global variables from command-line arguments
    globals()['CLEAR_TEXT'] = args.text
    # Strip any potential whitespace from the target cipher when it's set
    globals()['TARGET_CIPHER_BASE64'] = args.target.strip()
    globals()['CLEAR_TEXT_ENCODED'] = globals()['CLEAR_TEXT'].encode()

    # Initialize variables before the try block to ensure they are always defined
    attempts = 0
    start_time = time.time()
    last_report_time = start_time
    recent_keys_with_cipher = deque(maxlen=10) # Stores tuples of (key_string, generated_cipher_base64_string)

    use_dict_mode = args.dict is not None
    start_key_from_resume = None # Explicitly initialized
    is_resuming = False
    current_max_len_brute_force = args.length
    total_possible_keys = 0

    if use_dict_mode:
        all_keys_generator = read_keys_from_dict(args.dict, MAX_LEN_DICT_MODE)
        total_possible_keys = count_lines_in_file(args.dict)
        print(f"Starting dictionary mode search with '{args.dict}'...")
        # In dictionary mode, it does not resume from the current progress file.
        # Always starts from the beginning of the dictionary.
        clean_progress_file()
    else:
        # Calculate total possible keys for the entire search space
        total_possible_keys = count_total_brute_force_keys(CHARSET, current_max_len_brute_force)

        start_key_from_resume = load_progress() # This might update start_key_from_resume
        is_resuming = start_key_from_resume is not None
        
        if is_resuming:
            print(f"Resuming from key '{start_key_from_resume}'...")
            # Calculate the number of keys that were already processed up to the resume point
            # This requires iterating a dummy generator from the absolute beginning
            temp_generator_for_count = generate_all_keys(CHARSET, current_max_len_brute_force, start_key=None)
            keys_processed_before_resume = 0
            found_resume_key_in_sequence = False
            for key in temp_generator_for_count:
                keys_processed_before_resume += 1
                if key == start_key_from_resume:
                    found_resume_key_in_sequence = True
                    break
            
            if found_resume_key_in_sequence:
                attempts = keys_processed_before_resume
            else:
                # If resume key not found in sequence (e.g., corrupted file, or key was last in previous run)
                # We start fresh from the beginning, but this case should be rare if progress file is managed well.
                print(f"Warning: Resume key '{start_key_from_resume}' not found in sequence. Starting new search.")
                attempts = 0
                start_key_from_resume = None # Reset to None to ensure generator starts from beginning
                is_resuming = False # Reset resuming flag
            
            all_keys_generator = generate_all_keys(CHARSET, current_max_len_brute_force, start_key=start_key_from_resume)
        else:
            print("Starting new search...")
            attempts = 0
            all_keys_generator = generate_all_keys(CHARSET, current_max_len_brute_force, start_key=None)

    # Determines the number of processes to use.
    num_processes = multiprocessing.cpu_count()
    print(f"Using {num_processes} processes.")

    try:
        # Creates a pool of worker processes, passing the necessary global data to the initializer
        with multiprocessing.Pool(
            processes=num_processes,
            initializer=_worker_init,
            initargs=(globals()['TARGET_CIPHER_BASE64'], globals()['CLEAR_TEXT_ENCODED'], globals()['AES_BLOCK_SIZE'])
        ) as pool:
            # Unpack the three values returned by worker_decrypt
            for key_attempt_str, generated_cipher_base64, found_key_result in pool.imap_unordered(worker_decrypt, (k.encode() for k in all_keys_generator), chunksize=1000):
                attempts += 1 # Increment attempts for each key processed by the generator
                # Store both the key and its generated cipher
                recent_keys_with_cipher.append((key_attempt_str, generated_cipher_base64))

                if found_key_result:
                    elapsed = time.time() - start_time
                    display_stats(attempts, attempts / elapsed if elapsed > 0 else 0, recent_keys_with_cipher, elapsed, total_possible_keys, is_resuming, start_key_from_resume, use_dict_mode, args.dict, current_max_len_brute_force, final_display=True)
                    print("==================================================")
                    print("           ✅ KEY FOUND! ✅")
                    print("==================================================")
                    print(f"\n   Key found: '{found_key_result}'")
                    # The key padding logic is inside worker_decrypt, we reconstruct it for display
                    full_key_found = found_key_result.ljust(16, '\x00').encode()
                    print(f"   Full key (padded): {full_key_found}")
                    print(f"   Total Attempts: {attempts:,}")
                    print(f"   Time Elapsed: {format_elapsed_time(elapsed)}")
                    print("==================================================")
                    pool.terminate()
                    pool.join()
                    clean_progress_file()
                    return

                current_time = time.time()
                if current_time - last_report_time >= UPDATE_INTERVAL:
                    elapsed = current_time - start_time
                    speed = attempts / elapsed if elapsed > 0 else 0
                    display_stats(attempts, speed, recent_keys_with_cipher, elapsed, total_possible_keys, is_resuming, start_key_from_resume, use_dict_mode, args.dict, current_max_len_brute_force)
                    if not use_dict_mode:
                        save_progress(key_attempt_str)
                    last_report_time = current_time

            # If the loop finishes without finding the key (i.e., all_keys_generator is exhausted)
            elapsed = time.time() - start_time
            speed = attempts / elapsed if elapsed > 0 else 0
            if total_possible_keys == 0 and attempts > 0:
                total_possible_keys = attempts
            display_stats(attempts, speed, recent_keys_with_cipher, elapsed, total_possible_keys, is_resuming, start_key_from_resume, use_dict_mode, args.dict, current_max_len_brute_force, final_display=True)
            print("\n❌ Key not found in search space.")
            clean_progress_file()

    except KeyboardInterrupt:
        # Handles user interruption (Ctrl+C)
        clear_screen()
        print("\n==================================================")
        print("           🛑 PROCESS STOPPED BY USER 🛑")
        print("==================================================")
        # The progress file is kept to resume on the next run
    except Exception as e:
        # Captures any other exception that may occur
        clear_screen()
        print(f"\n==================================================")
        print(f"           ❌ AN ERROR OCCURRED: {e} ❌")
        print(f"==================================================")
    finally:
        # Ensures that final statistics are displayed upon completion,
        # even if there was an interruption or an error.
        elapsed = time.time() - start_time
        speed = attempts / elapsed if elapsed > 0 else 0
        # Ensure total_possible_keys is not zero before calculating percentage
        if total_possible_keys == 0 and attempts > 0:
            total_possible_keys = attempts
        print("\n==================================================")
        print("             SEARCH PROCESS ENDED                 ")
        print("==================================================")


if __name__ == "__main__":
    # It is crucial that code using multiprocessing.Pool is within an
    # if __name__ == "__main__": block to avoid issues on Windows.
    test_keys()
