"""
Utility functions for Bitcoin Private Key Finder
"""

import hashlib
import base58
import coincurve
import time
import json
import os
from datetime import datetime, timedelta
import multiprocessing

def format_int(n):
    """Format large integer with commas for readability"""
    return f"{n:,}"

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

def private_key_to_address(private_key_bytes, compressed=True):
    """Generate a Bitcoin address from a private key"""
    try:
        # Get the public key using coincurve
        pub_key = coincurve.PublicKey.from_secret(private_key_bytes)
        public_key_bytes = pub_key.format(compressed=compressed)
        
        # Hash160 of the public key
        pubkey_hash_bytes = hash160(public_key_bytes)
        
        # Calculate address
        address = calculate_address_from_pubkey_hash(pubkey_hash_bytes)
        return address, pubkey_hash_bytes.hex()
    except Exception as e:
        print(f"Error in key conversion: {str(e)}")
        raise

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

def save_match_to_file(match_data, filename="found_matches.json"):
    """Save match data to a JSON file"""
    try:
        # Use file locking for thread safety
        with multiprocessing.Lock():
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

def estimate_completion_time(keys_per_second, search_space_size, completion_percent=100):
    """Estimate time to complete a given percentage of the search"""
    if keys_per_second <= 0:
        return "infinity"
    
    keys_to_check = search_space_size * (completion_percent / 100)
    seconds_needed = keys_to_check / keys_per_second
    
    # Convert to timedelta for formatting
    time_needed = timedelta(seconds=seconds_needed)
    
    # Format differently based on duration
    if time_needed.total_seconds() < 60:
        return f"{time_needed.total_seconds():.2f} seconds"
    elif time_needed.total_seconds() < 3600:
        return f"{time_needed.total_seconds() / 60:.2f} minutes"
    elif time_needed.total_seconds() < 86400:
        return f"{time_needed.total_seconds() / 3600:.2f} hours"
    elif time_needed.total_seconds() < 86400 * 30:
        return f"{time_needed.total_seconds() / 86400:.2f} days"
    elif time_needed.total_seconds() < 86400 * 365:
        return f"{time_needed.total_seconds() / (86400 * 30):.2f} months"
    else:
        return f"{time_needed.total_seconds() / (86400 * 365):.2f} years"
