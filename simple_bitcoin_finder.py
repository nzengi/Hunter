#!/usr/bin/env python3
"""
Simple Bitcoin Private Key Finder
--------------------------------
Searches for the private key for Bitcoin address:
12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4

This is a streamlined version focused on reliable key generation and progress display.
"""

import hashlib
import random
import sys
import os
import time
import json
from datetime import datetime
import coincurve
import base58

# Target information
TARGET_ADDRESS = "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4"
TARGET_PUBKEY_HASH = "105b7f253f0ebd7843adaebbd805c944bfb863e4"
ADDRESS_PREFIX = "12VV"
ADDRESS_SUFFIX = "ysn4"
START_RANGE = 0x1000000000000000000
END_RANGE = 0x1ffffffffffffffffff

def hash160(data):
    """Perform SHA-256 and RIPEMD-160 hash functions"""
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    return ripemd160_hash.digest()

def double_sha256(data):
    """Perform double SHA-256 hash"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def private_key_to_address(private_key_bytes):
    """Generate a Bitcoin address from a private key"""
    try:
        # Get the public key using coincurve
        pub_key = coincurve.PublicKey.from_secret(private_key_bytes)
        public_key_bytes = pub_key.format(compressed=True)
        
        # Hash160 of the public key
        pubkey_hash_bytes = hash160(public_key_bytes)
        
        # Add version byte (0x00 for mainnet)
        versioned_hash = b'\x00' + pubkey_hash_bytes
        
        # Double SHA-256 checksum
        checksum = double_sha256(versioned_hash)[:4]
        
        # Base58Check encoding
        address = base58.b58encode(versioned_hash + checksum).decode('utf-8')
        
        return address, pubkey_hash_bytes.hex()
    except Exception as e:
        print(f"Error in key conversion: {str(e)}")
        return None, None

def generate_random_key():
    """Generate a random private key within the specified range"""
    # Generate a random value in the range
    range_size = END_RANGE - START_RANGE
    random_offset = random.randint(0, range_size - 1)
    private_key_int = START_RANGE + random_offset
    
    # Convert to bytes (32 bytes, big-endian)
    return private_key_int.to_bytes(32, byteorder='big')

def save_match(private_key_hex, address, pubkey_hash, match_type="pattern"):
    """Save a match to the JSON file"""
    match_data = {
        "address": address,
        "private_key": private_key_hex,
        "pubkey_hash": pubkey_hash,
        "match_type": match_type,
        "timestamp": datetime.now().isoformat()
    }
    
    filename = "found_matches.json"
    
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
        
        # Add new match
        data.append(match_data)
        
        # Write back to file
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
            
        print(f"\nMatch saved to {filename}")
    except Exception as e:
        print(f"\nError saving match: {str(e)}")

def check_key(private_key_bytes):
    """Check a single private key"""
    address, pubkey_hash = private_key_to_address(private_key_bytes)
    if address is None:
        return None
    
    result = None
    
    # Check for exact match
    if pubkey_hash == TARGET_PUBKEY_HASH:
        result = {
            "type": "exact",
            "address": address,
            "private_key": private_key_bytes.hex(),
            "pubkey_hash": pubkey_hash
        }
        print(f"\n🎉 EXACT MATCH FOUND! 🎉")
        print(f"Address:     {address}")
        print(f"Target:      {TARGET_ADDRESS}")
        print(f"Private Key: {private_key_bytes.hex()}")
        print(f"Pubkey Hash: {pubkey_hash}")
        
    # Check for prefix/suffix match
    elif address.startswith(ADDRESS_PREFIX) and address.endswith(ADDRESS_SUFFIX):
        result = {
            "type": "pattern",
            "address": address,
            "private_key": private_key_bytes.hex(),
            "pubkey_hash": pubkey_hash
        }
        print(f"\nFound pattern match: {address}")
        print(f"Private Key: {private_key_bytes.hex()}")
    
    return result

def format_number(n):
    """Format number with commas"""
    return f"{n:,}"

def format_time(seconds):
    """Format seconds to human-readable time"""
    if seconds < 60:
        return f"{seconds:.1f} sec"
    elif seconds < 3600:
        return f"{seconds/60:.1f} min"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hr"
    else:
        return f"{seconds/86400:.1f} days"

def main():
    print("Simple Bitcoin Private Key Finder")
    print("--------------------------------")
    print(f"Target: {TARGET_ADDRESS}")
    print(f"Public Key Hash: {TARGET_PUBKEY_HASH}")
    print(f"Range: 0x{START_RANGE:x} to 0x{END_RANGE:x}")
    print(f"Looking for addresses with prefix '{ADDRESS_PREFIX}' and suffix '{ADDRESS_SUFFIX}'")
    
    # Initialize counter and timer
    keys_checked = 0
    start_time = time.time()
    last_update_time = start_time
    update_interval = 1.0  # Update display every second
    
    try:
        while True:
            # Generate and check a random key
            private_key = generate_random_key()
            result = check_key(private_key)
            keys_checked += 1
            
            # Save match if found
            if result:
                save_match(
                    result["private_key"],
                    result["address"],
                    result["pubkey_hash"],
                    result["type"]
                )
                
                # Exit if exact match found
                if result["type"] == "exact":
                    print("\nExact match found! Search complete.")
                    break
            
            # Update statistics periodically
            current_time = time.time()
            if current_time - last_update_time >= update_interval:
                elapsed = current_time - start_time
                keys_per_second = keys_checked / elapsed if elapsed > 0 else 0
                
                # Calculate range coverage
                range_size = END_RANGE - START_RANGE
                percent_covered = (keys_checked * 100.0) / range_size if range_size > 0 else 0
                
                # Estimate time to complete
                keys_remaining = range_size - keys_checked
                time_remaining = keys_remaining / keys_per_second if keys_per_second > 0 else float('inf')
                
                # Display statistics
                sys.stdout.write(f"\rKeys checked: {format_number(keys_checked)} @ {format_number(int(keys_per_second))}/sec | " +
                                f"Elapsed: {format_time(elapsed)} | " +
                                f"Progress: {percent_covered:.12f}% | " +
                                f"ETA: {format_time(time_remaining)}")
                sys.stdout.flush()
                
                last_update_time = current_time
                
    except KeyboardInterrupt:
        print("\nSearch interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    
    # Final statistics
    elapsed = time.time() - start_time
    print(f"\nSearch completed.")
    print(f"Total keys checked: {format_number(keys_checked)}")
    print(f"Speed: {format_number(int(keys_checked / elapsed))} keys/sec")
    print(f"Total time: {format_time(elapsed)}")
    
    return 0

if __name__ == "__main__":
    # Set random seed
    random.seed()
    
    # Start search
    sys.exit(main())