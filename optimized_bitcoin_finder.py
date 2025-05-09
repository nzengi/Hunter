#!/usr/bin/env python3
"""
Multi-Core CPU Optimized Bitcoin Private Key Finder
--------------------------------------------------
Searches for a specific Bitcoin address within a defined key range
using multiple CPU cores for maximum performance.

Target: Find the private key for 12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4
Range: 0x1000000000000000000 to 0x1ffffffffffffffffff
"""

import hashlib
import random
import binascii
import sys
import os
import time
import json
import multiprocessing
from multiprocessing import Pool, cpu_count
import coincurve
import base58
from datetime import datetime

# Default values for Bitcoin Puzzle #73
DEFAULT_START_RANGE = 0x1000000000000000000
DEFAULT_END_RANGE = 0x1ffffffffffffffffff
DEFAULT_TARGET_ADDRESS = "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4"
DEFAULT_TARGET_PUBKEY_HASH = "105b7f253f0ebd7843adaebbd805c944bfb863e4"
DEFAULT_PREFIX = "12VV"
DEFAULT_SUFFIX = "ysn4"

# Global stats variables
total_keys_checked = multiprocessing.Value('i', 0)
start_time = time.time()
running = True

def format_int(n):
    """Format large integer with commas for readability"""
    return f"{n:,}"

def get_human_readable_time(seconds):
    """Convert seconds to human-readable time format"""
    if seconds < 60:
        return f"{seconds:.2f} sec"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} min"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.2f} hr"
    else:
        days = seconds / 86400
        return f"{days:.2f} days"

def hash160(data):
    """Perform SHA-256 and RIPEMD-160 hash functions"""
    # Use built-in function from coincurve if it's a public key
    if isinstance(data, coincurve.PublicKey):
        return data.hash
    
    # Otherwise do it manually
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    return ripemd160_hash.digest()

def double_sha256(data):
    """Perform double SHA-256 hash"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def calculate_address_from_pubkey_hash(pubkey_hash_bytes):
    """Calculate Bitcoin address from public key hash"""
    # Add version byte (0x00 for mainnet)
    versioned_hash = b'\x00' + pubkey_hash_bytes
    
    # Double SHA-256 checksum
    checksum = double_sha256(versioned_hash)[:4]
    
    # Base58Check encoding
    address = base58.b58encode(versioned_hash + checksum).decode('utf-8')
    return address

def private_key_to_address(private_key, compressed=True):
    """Generate a compressed Bitcoin address from a private key using coincurve"""
    try:
        if isinstance(private_key, str):
            private_key = bytes.fromhex(private_key)
        
        # Get the public key using coincurve (faster)
        pub_key = coincurve.PublicKey.from_secret(private_key)
        public_key_bytes = pub_key.format(compressed=compressed)
        
        # Hash160 of the public key
        pubkey_hash_bytes = hash160(public_key_bytes)
        
        # Calculate address
        address = calculate_address_from_pubkey_hash(pubkey_hash_bytes)
        return address, pubkey_hash_bytes.hex()
    except Exception as e:
        print(f"Error in key conversion: {str(e)}")
        raise

def check_address_match(address, prefix, suffix):
    """Check if address starts with prefix and ends with suffix"""
    if address.startswith(prefix) and address.endswith(suffix):
        return True
    return False

def save_match_to_file(match_data, filename="found_matches.json"):
    """Save match data to a JSON file"""
    try:
        # Load existing data if file exists
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
        else:
            data = []
        
        # Append new match
        data.append(match_data)
        
        # Write back to file
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
            
        print(f"\nMatch saved to {filename}")
    except Exception as e:
        print(f"\nError saving match to file: {str(e)}")

def generate_sequential_private_keys(start_key, num_keys, step=1):
    """Generate a batch of sequential private keys"""
    for i in range(num_keys):
        # Ensure we don't exceed the maximum 256-bit integer value
        current_key = min(start_key + i * step, (1 << 256) - 1)
        yield current_key.to_bytes(32, byteorder='big')

def process_batch(args):
    """Process a batch of private keys"""
    batch_start, batch_size, step, prefix, suffix, target_address, target_pubkey_hash = args
    exact_match = False
    matches = []
    keys_checked_local = 0
    
    try:
        # Generate private keys within the range
        for private_key in generate_sequential_private_keys(batch_start, batch_size, step):
            keys_checked_local += 1
            
            # First check if the private key would generate the target pubkey hash
            # This is faster than generating the full address
            pub_key = coincurve.PublicKey.from_secret(private_key)
            pubkey_hash_bytes = hash160(pub_key.format(compressed=True))
            pubkey_hash = pubkey_hash_bytes.hex()
            
            # Fast check for exact match using pubkey hash
            if pubkey_hash == target_pubkey_hash:
                address = calculate_address_from_pubkey_hash(pubkey_hash_bytes)
                match_data = {
                    "address": address,
                    "private_key_hex": private_key.hex(),
                    "pubkey_hash": pubkey_hash,
                    "match_type": "exact",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                matches.append(match_data)
                exact_match = True
                
                # Print match info
                print(f"\n🎉 EXACT MATCH FOUND! 🎉")
                print(f"Address: {address}")
                print(f"Private Key (hex): {private_key.hex()}")
                print(f"Public Key Hash: {pubkey_hash}")
                
                # We found the exact match, no need to check more
                break
            
            # Check prefix/suffix only if specified
            if prefix or suffix:
                address = calculate_address_from_pubkey_hash(pubkey_hash_bytes)
                
                if check_address_match(address, prefix, suffix):
                    match_data = {
                        "address": address,
                        "private_key_hex": private_key.hex(),
                        "pubkey_hash": pubkey_hash,
                        "match_type": "prefix_suffix",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    matches.append(match_data)
                    
                    # Print match info
                    print(f"\nFound matching address: {address}")
                    print(f"Private Key (hex): {private_key.hex()}")
                    print(f"Public Key Hash: {pubkey_hash}")
    except Exception as e:
        print(f"\nError in worker: {str(e)}")
    
    # Update global counter
    with total_keys_checked.get_lock():
        total_keys_checked.value += keys_checked_local
    
    # Return results
    return {
        "exact_match": exact_match,
        "matches": matches,
        "keys_checked": keys_checked_local
    }

def optimize_batch_size(workers):
    """Determine optimal batch size based on available CPU cores"""
    # Define batch size based on CPU count - more cores allows for smaller batches
    # which improves responsiveness
    base_size = 5000
    cores = max(1, workers)
    
    # Use smaller batches for more cores for better responsiveness
    if cores <= 2:
        return base_size
    elif cores <= 4:
        return base_size // 2
    elif cores <= 8:
        return base_size // 4
    else:
        return base_size // 8

def update_statistics(keys_checked, start_time, search_range_start, search_range_end, with_newline=False):
    """Display search statistics"""
    current_time = time.time()
    elapsed = current_time - start_time
    keys_per_second = keys_checked / elapsed if elapsed > 0 else 0
    
    # Calculate search space size and coverage
    search_space_size = search_range_end - search_range_start
    percent_covered = (keys_checked * 100.0) / search_space_size
    
    # Estimate time to complete 100% and 1% of the search
    time_to_complete = search_space_size / keys_per_second if keys_per_second > 0 else float('inf')
    time_to_1_percent = (search_space_size * 0.01) / keys_per_second if keys_per_second > 0 else float('inf')
    
    end_char = "\n" if with_newline else "\r"
    
    # Print statistics
    print(f"{end_char}Keys checked: {format_int(keys_checked)} @ {format_int(keys_per_second)}/sec | "
          f"Coverage: {percent_covered:.10f}% | "
          f"Runtime: {get_human_readable_time(elapsed)} | "
          f"Est. 1%: {get_human_readable_time(time_to_1_percent)}", end="")
    
    sys.stdout.flush()

def main(target_address=DEFAULT_TARGET_ADDRESS, 
         target_pubkey_hash=DEFAULT_TARGET_PUBKEY_HASH,
         prefix=DEFAULT_PREFIX, 
         suffix=DEFAULT_SUFFIX,
         start_range=DEFAULT_START_RANGE, 
         end_range=DEFAULT_END_RANGE):
    
    global start_time
    
    print("Starting multi-core optimized Bitcoin address search...")
    print(f"Looking for addresses with prefix: {prefix} and suffix: {suffix}")
    print(f"Target address: {target_address}")
    print(f"Target pubkey hash: {target_pubkey_hash}")
    print(f"Search range: 0x{start_range:x} - 0x{end_range:x}")
    
    # Determine optimal CPU core usage
    max_workers = cpu_count()
    workers = max(1, max_workers - 1)  # Leave one core free for system
    print(f"Using {workers} of {max_workers} available CPU cores")
    
    # Determine batch size
    batch_size = optimize_batch_size(workers)
    print(f"Using batch size: {format_int(batch_size)} keys per worker")
    
    # Calculate step size to distribute workload - use smaller step for better distribution
    step_size = max(1, (end_range - start_range) // (workers * 1000000))
    print(f"Using step size: {format_int(step_size)} for workload distribution")
    
    # Create Pool
    pool = Pool(processes=workers)
    
    # Initialize timers
    start_time = time.time()
    last_status_time = time.time()
    update_interval = 2.0  # Update status every 2 seconds
    
    # Variable to track if exact match found
    found_exact_match = False
    
    # Initialize current ranges for each worker
    current_ranges = [start_range + i * step_size for i in range(workers)]
    
    try:
        while not found_exact_match and min(current_ranges) < end_range:
            # Create work batches
            batches = []
            for i in range(workers):
                if current_ranges[i] < end_range:
                    batches.append((current_ranges[i], batch_size, step_size * workers, 
                                    prefix, suffix, target_address, target_pubkey_hash))
                    current_ranges[i] += batch_size * step_size * workers
            
            # Process batches in parallel
            results = pool.map(process_batch, batches)
            
            # Process results
            for result in results:
                if result["exact_match"]:
                    found_exact_match = True
                    exact_match = [m for m in result["matches"] if m["match_type"] == "exact"][0]
                    
                    # Final statistics update
                    update_statistics(total_keys_checked.value, start_time, start_range, end_range, True)
                    
                    # Print success message
                    print(f"\nSUCCESS! Found EXACT match for target address: {target_address}")
                    print(f"Private key: {exact_match['private_key_hex']}")
                    print(f"Public Key Hash: {exact_match['pubkey_hash']}")
                    break
                
                for match in result["matches"]:
                    save_match_to_file(match)
            
            # Update statistics periodically
            current_time = time.time()
            if current_time - last_status_time > update_interval:
                update_statistics(total_keys_checked.value, start_time, start_range, end_range)
                last_status_time = current_time
        
        # Final update
        if not found_exact_match:
            update_statistics(total_keys_checked.value, start_time, start_range, end_range, True)
            print("\nSearch completed. No exact match found.")
    
    except KeyboardInterrupt:
        print("\nSearch interrupted by user.")
    except Exception as e:
        print(f"\nError in main loop: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        # Make sure we clean up the Pool
        pool.close()
        pool.join()
    
    print("\nSearch complete!")
    return None

if __name__ == "__main__":
    # Set the starting method for better multiprocessing
    multiprocessing.set_start_method('spawn', force=True)
    
    # Initialize random seed
    random.seed()
    
    # Run the main search
    main()