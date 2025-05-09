#!/usr/bin/env python3
"""
Bitcoin Private Key Searcher
----------------------------
Efficient implementation to search for Bitcoin private keys for address:
12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4

This version focuses on high performance and clear progress reporting.
"""

import hashlib
import time
import os
import sys
import json
from datetime import datetime
import multiprocessing
from multiprocessing import Pool, cpu_count, Value
import coincurve
import base58
import random

# Target information
TARGET_ADDRESS = "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4"
TARGET_PUBKEY_HASH = "105b7f253f0ebd7843adaebbd805c944bfb863e4"
ADDRESS_PREFIX = "12VV"
ADDRESS_SUFFIX = "ysn4"
START_RANGE = 0x1000000000000000000
END_RANGE = 0x1ffffffffffffffffff

# Global counter for keys checked
keys_checked = Value('i', 0)

def hash160(data):
    """Perform RIPEMD160(SHA256(data))"""
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    return ripemd160.digest()

def double_sha256(data):
    """Perform SHA256(SHA256(data))"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def private_key_to_address(private_key_bytes):
    """Convert a private key to a Bitcoin address"""
    # Get public key
    pub_key = coincurve.PublicKey.from_secret(private_key_bytes)
    pubkey_bytes = pub_key.format(compressed=True)
    
    # Get public key hash (RIPEMD160 of SHA256)
    pubkey_hash = hash160(pubkey_bytes)
    
    # Create versioned payload (version + pubkey_hash)
    versioned_payload = b'\x00' + pubkey_hash
    
    # Calculate checksum
    checksum = double_sha256(versioned_payload)[:4]
    
    # Create final binary address
    binary_addr = versioned_payload + checksum
    
    # Encode in Base58
    address = base58.b58encode(binary_addr).decode('utf-8')
    
    return address, pubkey_hash.hex()

def check_key(private_key_int):
    """Check a single private key"""
    # Convert integer to bytes
    private_key_bytes = private_key_int.to_bytes(32, byteorder='big')
    
    # Calculate address
    address, pubkey_hash = private_key_to_address(private_key_bytes)
    
    # First check direct hash match (faster)
    if pubkey_hash == TARGET_PUBKEY_HASH:
        return {
            "match_type": "exact",
            "address": address,
            "private_key": private_key_bytes.hex(),
            "pubkey_hash": pubkey_hash
        }
    
    # Then check prefix/suffix match
    if address.startswith(ADDRESS_PREFIX) and address.endswith(ADDRESS_SUFFIX):
        return {
            "match_type": "pattern",
            "address": address,
            "private_key": private_key_bytes.hex(),
            "pubkey_hash": pubkey_hash
        }
    
    return None

def worker_task(args):
    """Worker process to check a range of keys"""
    start_key, num_keys, worker_id = args
    local_matches = []
    local_keys_checked = 0
    
    # Update counter at beginning to show progress immediately
    with keys_checked.get_lock():
        keys_checked.value += 1
    
    # Every worker will test keys
    for i in range(num_keys):
        # Calculate key to check - ensure we're within range
        key_int = start_key + i
        if key_int > END_RANGE:
            key_int = START_RANGE + (key_int % (END_RANGE - START_RANGE))
        
        try:
            # Check the key
            result = check_key(key_int)
            local_keys_checked += 1
            
            # If we found a match, record it
            if result:
                # Add timestamp and worker info
                result["timestamp"] = datetime.now().isoformat()
                result["worker_id"] = worker_id
                local_matches.append(result)
                
                # For exact match, can exit early
                if result["match_type"] == "exact":
                    break
            
            # Update global counter frequently
            if i % 5 == 0:
                with keys_checked.get_lock():
                    keys_checked.value += 5
        except Exception as e:
            print(f"Error processing key {key_int}: {e}")
    
    # Update counter one final time
    remaining = local_keys_checked % 5
    if remaining > 0:
        with keys_checked.get_lock():
            keys_checked.value += remaining
    
    return local_matches

def save_results(matches, filename="found_matches.json"):
    """Save matches to a JSON file"""
    if not matches:
        return
    
    # Create or append to file
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                try:
                    existing_data = json.load(f)
                except json.JSONDecodeError:
                    existing_data = []
        else:
            existing_data = []
        
        # Add new matches
        existing_data.extend(matches)
        
        # Write back to file
        with open(filename, 'w') as f:
            json.dump(existing_data, f, indent=2)
        
        print(f"✓ Saved {len(matches)} matches to {filename}")
    except Exception as e:
        print(f"Error saving results: {e}")

def format_number(n):
    """Format a number with commas for readability"""
    return f"{n:,}"

def format_time(seconds):
    """Format seconds into a human-readable time string"""
    if seconds < 60:
        return f"{seconds:.1f} sec"
    elif seconds < 3600:
        return f"{seconds/60:.1f} min"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hr"
    else:
        return f"{seconds/86400:.1f} days"

def display_stats(start_time, checked, total, print_newline=False):
    """Display search statistics"""
    elapsed = time.time() - start_time
    speed = checked / elapsed if elapsed > 0 else 0
    progress = (checked / total) * 100 if total > 0 else 0
    
    time_to_complete = (total - checked) / speed if speed > 0 else float('inf')
    
    end_char = "\n" if print_newline else "\r"
    
    speed_formatted = format_number(int(speed))
    
    sys.stdout.write(f"{end_char}Keys: {format_number(checked)} @ {speed_formatted}/sec | " +
                    f"Progress: {progress:.10f}% | " +
                    f"Elapsed: {format_time(elapsed)} | " +
                    f"ETA: {format_time(time_to_complete)}")
    sys.stdout.flush()

def main():
    """Main function to coordinate the search"""
    print("Bitcoin Private Key Finder")
    print("-------------------------")
    print(f"Target Address:   {TARGET_ADDRESS}")
    print(f"Public Key Hash:  {TARGET_PUBKEY_HASH}")
    print(f"Looking for keys in range: 0x{START_RANGE:x} to 0x{END_RANGE:x}")
    
    # Determine number of workers (use all but one core)
    num_cores = cpu_count()
    num_workers = max(1, num_cores - 1)
    print(f"Using {num_workers} worker processes")
    
    # Calculate range size
    range_size = END_RANGE - START_RANGE
    
    # Calculate batch size (smaller is more responsive, larger is more efficient)
    keys_per_batch = 500
    
    # Calculate search strategy
    search_width = max(1, range_size // (1000 * num_workers))
    print(f"Search strategy: Sampling across full range with step size {format_number(search_width)}")
    
    # Initialize multiprocessing
    pool = Pool(processes=num_workers)
    
    # Initialize statistics
    start_time = time.time()
    last_display_time = time.time()
    display_interval = 1.0  # seconds
    all_matches = []
    
    try:
        # For random searching, generate random starting points across the range
        print("Starting search...")
        batch_count = 0
        
        while True:
            batch_count += 1
            batch_tasks = []
            
            # Generate tasks for each worker
            for worker_id in range(num_workers):
                # For each worker, pick a random starting point in the range
                random_start = random.randint(START_RANGE, END_RANGE - keys_per_batch)
                batch_tasks.append((random_start, keys_per_batch, worker_id))
            
            # Process this batch
            batch_results = pool.map(worker_task, batch_tasks)
            
            # Collect matches
            for worker_matches in batch_results:
                if worker_matches:
                    # We found one or more matches!
                    all_matches.extend(worker_matches)
                    
                    # Check for exact match
                    exact_matches = [m for m in worker_matches if m["match_type"] == "exact"]
                    if exact_matches:
                        print("\n🎉 EXACT MATCH FOUND! 🎉")
                        for match in exact_matches:
                            print(f"Address:     {match['address']}")
                            print(f"Private Key: {match['private_key']}")
                            print(f"Pubkey Hash: {match['pubkey_hash']}")
                        
                        # Save results and exit
                        save_results(all_matches)
                        return True
            
            # Display progress periodically
            current_time = time.time()
            if current_time - last_display_time >= display_interval:
                display_stats(start_time, keys_checked.value, range_size)
                last_display_time = current_time
            
            # Save matches periodically
            if batch_count % 10 == 0 and all_matches:
                save_results(all_matches)
                all_matches = []  # Clear after saving
    
    except KeyboardInterrupt:
        print("\nSearch interrupted by user.")
    except Exception as e:
        print(f"\nError in main loop: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Final stats update
        display_stats(start_time, keys_checked.value, range_size, True)
        
        # Save any remaining matches
        if all_matches:
            save_results(all_matches)
        
        # Clean up
        pool.close()
        pool.join()
    
    print("\nSearch finished.")
    return False

if __name__ == "__main__":
    # Set the spawning method for better compatibility
    multiprocessing.set_start_method('spawn', force=True)
    sys.exit(0 if main() else 1)