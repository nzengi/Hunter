#!/usr/bin/env python3
"""
GPU-accelerated Bitcoin Private Key Finder
------------------------------------------
Searches for a specific Bitcoin address within a defined key range
using GPU acceleration (CUDA) for maximum performance.

Target: Find the private key for 12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4
Range: 0x1000000000000000000 to 0x1ffffffffffffffffff
"""

import argparse
import hashlib
import time
import os
import json
import sys
import binascii
import signal
import math
from datetime import datetime, timedelta

import numpy as np
import pycuda.driver as cuda
import pycuda.autoinit
from pycuda.compiler import SourceModule
import base58
import coincurve

from utils import (
    format_int, calculate_address_from_pubkey_hash, double_sha256,
    save_match_to_file, hash160, get_human_readable_time
)
from cuda_kernels import cuda_kernel_code

# Default values for Bitcoin Puzzle #73
DEFAULT_START_RANGE = 0x1000000000000000000
DEFAULT_END_RANGE = 0x1ffffffffffffffffff
DEFAULT_TARGET_ADDRESS = "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4"
DEFAULT_TARGET_PUBKEY_HASH = "105b7f253f0ebd7843adaebbd805c944bfb863e4"
DEFAULT_PREFIX = "12VV"
DEFAULT_SUFFIX = "ysn4"

# Statistics and monitoring
keys_checked = 0
start_time = 0
running = True
last_update_time = 0
UPDATE_INTERVAL = 2  # Update status every 2 seconds

def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully shut down"""
    global running
    print("\nStopping... (This may take a moment to clean up GPU resources)")
    running = False

def get_device_info():
    """Get information about the CUDA-capable device"""
    device = cuda.Device(0)
    return {
        "name": device.name(),
        "compute_capability": f"{device.compute_capability()[0]}.{device.compute_capability()[1]}",
        "total_memory": device.total_memory() // (1024**2),
        "multiprocessors": device.get_attribute(cuda.device_attribute.MULTIPROCESSOR_COUNT),
        "max_threads_per_block": device.get_attribute(cuda.device_attribute.MAX_THREADS_PER_BLOCK),
        "warp_size": device.get_attribute(cuda.device_attribute.WARP_SIZE)
    }

def initialize_kernel(batch_size, threads_per_block=256):
    """Initialize the CUDA kernel for private key generation and validation"""
    # Compile the CUDA kernel
    module = SourceModule(cuda_kernel_code)
    kernel = module.get_function("generate_and_check_addresses")
    
    # Calculate block dimensions
    blocks = (batch_size + threads_per_block - 1) // threads_per_block
    
    return kernel, (blocks, 1, 1), (threads_per_block, 1, 1)

def prepare_kernel_arguments(batch_size, start_range):
    """Prepare data structures for the CUDA kernel"""
    # Create arrays for random values, private keys, and result flags
    # We'll use random values as seed, and the kernel will generate private keys
    random_values = np.random.randint(0, 2**32-1, size=batch_size, dtype=np.uint32)
    
    # Array to store if match found (1) or not (0)
    match_results = np.zeros(batch_size, dtype=np.int32)
    
    # Array to store private keys (only used for matches)
    private_keys = np.zeros((batch_size, 8), dtype=np.uint32)  # 256-bit keys stored as 8 x 32-bit values
    
    # Array to store pubkey hash results (only for matches)
    pubkey_hashes = np.zeros((batch_size, 20), dtype=np.uint8)
    
    # Convert range start to array (we add batch index in the kernel)
    range_start = np.array([(start_range >> 224) & 0xFFFFFFFF,
                           (start_range >> 192) & 0xFFFFFFFF,
                           (start_range >> 160) & 0xFFFFFFFF,
                           (start_range >> 128) & 0xFFFFFFFF,
                           (start_range >> 96) & 0xFFFFFFFF,
                           (start_range >> 64) & 0xFFFFFFFF,
                           (start_range >> 32) & 0xFFFFFFFF,
                           start_range & 0xFFFFFFFF], dtype=np.uint32)
    
    # Create arrays on the GPU
    gpu_random_values = cuda.mem_alloc(random_values.nbytes)
    gpu_match_results = cuda.mem_alloc(match_results.nbytes)
    gpu_private_keys = cuda.mem_alloc(private_keys.nbytes)
    gpu_pubkey_hashes = cuda.mem_alloc(pubkey_hashes.nbytes)
    gpu_range_start = cuda.mem_alloc(range_start.nbytes)
    
    # Copy data to GPU
    cuda.memcpy_htod(gpu_random_values, random_values)
    cuda.memcpy_htod(gpu_match_results, match_results)
    cuda.memcpy_htod(gpu_private_keys, private_keys)
    cuda.memcpy_htod(gpu_pubkey_hashes, pubkey_hashes)
    cuda.memcpy_htod(gpu_range_start, range_start)
    
    return {
        "random_values": random_values,
        "match_results": match_results,
        "private_keys": private_keys,
        "pubkey_hashes": pubkey_hashes,
        "range_start": range_start,
        "gpu_random_values": gpu_random_values,
        "gpu_match_results": gpu_match_results,
        "gpu_private_keys": gpu_private_keys,
        "gpu_pubkey_hashes": gpu_pubkey_hashes,
        "gpu_range_start": gpu_range_start,
    }

def process_matches(data, target_pubkey_hash, target_address, prefix, suffix):
    """Process and validate matches from the GPU"""
    # Copy result data back from the GPU
    cuda.memcpy_dtoh(data["match_results"], data["gpu_match_results"])
    
    # Check if we have any matches
    if np.any(data["match_results"] > 0):
        print("\nPotential matches found! Validating...")
        
        # Copy private keys and pubkey hashes for matches
        cuda.memcpy_dtoh(data["private_keys"], data["gpu_private_keys"])
        cuda.memcpy_dtoh(data["pubkey_hashes"], data["gpu_pubkey_hashes"])
        
        # Process each match
        matches = []
        for i in range(len(data["match_results"])):
            # Different match types - 1: prefix/suffix, 2: exact match
            match_type = data["match_results"][i]
            if match_type > 0:
                # Extract the private key (convert from 8 uint32 to bytes)
                private_key_parts = data["private_keys"][i]
                private_key_int = 0
                for j in range(8):
                    private_key_int = (private_key_int << 32) | private_key_parts[j]
                
                private_key_bytes = private_key_int.to_bytes(32, byteorder='big')
                private_key_hex = private_key_bytes.hex()
                
                # Re-compute the address to double-check
                try:
                    pub_key = coincurve.PublicKey.from_secret(private_key_bytes)
                    pubkey_hash_bytes = hash160(pub_key.format(compressed=True))
                    address = calculate_address_from_pubkey_hash(pubkey_hash_bytes)
                    
                    # Store and validate the match
                    pubkey_hash = pubkey_hash_bytes.hex()
                    match_data = {
                        "address": address,
                        "private_key_hex": private_key_hex,
                        "pubkey_hash": pubkey_hash,
                        "match_type": "exact" if match_type == 2 else "prefix_suffix",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    # Validate exact match or prefix/suffix
                    if match_type == 2 and pubkey_hash == target_pubkey_hash:
                        print(f"\n🎉 EXACT MATCH FOUND! 🎉")
                        print(f"Address: {address}")
                        print(f"Target: {target_address}")
                        print(f"Private Key (hex): {private_key_hex}")
                        print(f"Public Key Hash: {pubkey_hash}")
                        matches.append(match_data)
                        save_match_to_file(match_data)
                        return True, match_data
                    elif match_type == 1 and address.startswith(prefix) and address.endswith(suffix):
                        print(f"Found prefix/suffix match: {address}")
                        print(f"Private Key (hex): {private_key_hex}")
                        matches.append(match_data)
                        save_match_to_file(match_data)
                except Exception as e:
                    print(f"Error validating match: {str(e)}")
        
        return False, matches
    
    return False, []

def get_optimal_batch_size(device_info):
    """Calculate optimal batch size based on GPU specs"""
    # Use a multiple of warp size and consider memory constraints
    warp_size = device_info['warp_size']
    multiprocessors = device_info['multiprocessors']
    
    # Start with a base calculation considering GPU architecture
    # Each multiprocessor can handle multiple warps
    base_size = warp_size * 32 * multiprocessors
    
    # Adjust based on available memory (use at most 70% of available memory)
    mem_mb = device_info['total_memory']
    # Each key check needs roughly 256 bytes for private key, public key, and temp data
    max_keys_by_mem = (mem_mb * 1024 * 1024 * 0.7) // 256
    
    # Choose the smaller of the two constraints
    optimal_size = min(base_size, max_keys_by_mem)
    
    # Round to nearest multiple of warp_size * 32 for optimal execution
    batch_multiple = warp_size * 32
    return int(math.floor(optimal_size / batch_multiple) * batch_multiple)

def update_statistics(batch_size):
    """Update and display search statistics"""
    global keys_checked, start_time, last_update_time
    
    keys_checked += batch_size
    current_time = time.time()
    
    # Throttle updates to avoid excessive console output
    if current_time - last_update_time < UPDATE_INTERVAL and keys_checked < batch_size * 2:
        return
    
    elapsed_time = current_time - start_time
    keys_per_second = keys_checked / elapsed_time if elapsed_time > 0 else 0
    
    # Calculate search space size and coverage
    search_space_size = DEFAULT_END_RANGE - DEFAULT_START_RANGE
    percent_covered = (keys_checked * 100.0) / search_space_size
    
    # Estimate time to complete 100% and 1% of the search
    estimated_total_time = search_space_size / keys_per_second if keys_per_second > 0 else float('inf')
    estimated_1percent_time = (search_space_size * 0.01) / keys_per_second if keys_per_second > 0 else float('inf')
    
    # Clear previous output line
    sys.stdout.write("\033[K")  # Clear line
    
    # Print statistics
    print(f"\rKeys checked: {format_int(keys_checked)} @ {format_int(keys_per_second)}/sec | "
          f"Coverage: {percent_covered:.10f}% | "
          f"Runtime: {get_human_readable_time(elapsed_time)} | "
          f"Est. 1%: {get_human_readable_time(estimated_1percent_time)}", end="")
    
    sys.stdout.flush()
    last_update_time = current_time

def main():
    global start_time, keys_checked
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description='GPU-accelerated Bitcoin Private Key Finder')
    parser.add_argument('--start', type=lambda x: int(x, 0), 
                        default=DEFAULT_START_RANGE, help='Start of key range (hex or decimal)')
    parser.add_argument('--end', type=lambda x: int(x, 0), 
                        default=DEFAULT_END_RANGE, help='End of key range (hex or decimal)')
    parser.add_argument('--target', type=str, 
                        default=DEFAULT_TARGET_ADDRESS, help='Target Bitcoin address')
    parser.add_argument('--prefix', type=str, 
                        default=DEFAULT_PREFIX, help='Address prefix to match')
    parser.add_argument('--suffix', type=str, 
                        default=DEFAULT_SUFFIX, help='Address suffix to match')
    parser.add_argument('--pubkeyhash', type=str, 
                        default=DEFAULT_TARGET_PUBKEY_HASH, help='Target public key hash (RIPEMD-160)')
    args = parser.parse_args()
    
    # Initialize variables
    target_address = args.target
    target_pubkey_hash = args.pubkeyhash
    prefix = args.prefix
    suffix = args.suffix
    current_range = args.start
    end_range = args.end
    
    # Get GPU device information
    device_info = get_device_info()
    print(f"GPU Device: {device_info['name']}")
    print(f"Compute Capability: {device_info['compute_capability']}")
    print(f"Memory: {device_info['total_memory']} MB")
    print(f"Multiprocessors: {device_info['multiprocessors']}")
    
    # Calculate optimal batch size
    batch_size = get_optimal_batch_size(device_info)
    print(f"Using batch size: {format_int(batch_size)} keys per iteration")
    
    # Initialize the CUDA kernel
    kernel, grid, block = initialize_kernel(batch_size)
    print(f"CUDA configuration: Grid={grid}, Block={block}")
    
    # Setup for the target address
    target_pubkey_hash_bytes = bytes.fromhex(target_pubkey_hash)
    
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    print("\nStarting search...")
    print(f"Looking for addresses with prefix: {prefix} and suffix: {suffix}")
    print(f"Target address: {target_address}")
    print(f"Target pubkey hash: {target_pubkey_hash}")
    print(f"Search range: 0x{current_range:x} - 0x{end_range:x}")
    
    # Start timing
    start_time = time.time()
    keys_checked = 0
    
    try:
        # Main search loop
        while running and current_range < end_range:
            # Prepare kernel arguments
            data = prepare_kernel_arguments(batch_size, current_range)
            
            # Execute the kernel
            kernel(
                data["gpu_random_values"],
                data["gpu_match_results"],
                data["gpu_private_keys"],
                data["gpu_pubkey_hashes"],
                data["gpu_range_start"],
                np.uint32(batch_size),
                # Target pubkey hash as 5 uint32 (20 bytes)
                np.uint32(int.from_bytes(target_pubkey_hash_bytes[0:4], byteorder='big')),
                np.uint32(int.from_bytes(target_pubkey_hash_bytes[4:8], byteorder='big')),
                np.uint32(int.from_bytes(target_pubkey_hash_bytes[8:12], byteorder='big')),
                np.uint32(int.from_bytes(target_pubkey_hash_bytes[12:16], byteorder='big')),
                np.uint32(int.from_bytes(target_pubkey_hash_bytes[16:20], byteorder='big')),
                # Prefix and suffix as numeric representation (first/last 4 chars)
                np.uint32(int.from_bytes(prefix[:min(4, len(prefix))].encode(), byteorder='big')),
                np.uint32(int.from_bytes(suffix[-min(4, len(suffix)):].encode(), byteorder='big')),
                np.uint32(len(prefix)),
                np.uint32(len(suffix)),
                block=block, grid=grid
            )
            
            # Process potential matches
            found_exact, matches = process_matches(data, target_pubkey_hash, target_address, prefix, suffix)
            
            # Update statistics
            update_statistics(batch_size)
            
            # Free GPU memory
            for gpu_array in [data["gpu_random_values"], data["gpu_match_results"], 
                              data["gpu_private_keys"], data["gpu_pubkey_hashes"], 
                              data["gpu_range_start"]]:
                gpu_array.free()
            
            # Exit if exact match found
            if found_exact:
                print("\nSearch completed successfully! Exact match found.")
                return matches
            
            # Move to next batch
            current_range += batch_size
            
        # End of search or interrupted
        elapsed_time = time.time() - start_time
        if current_range >= end_range:
            print("\nSearch completed. Entire range searched.")
        
        print(f"\nFinal statistics:")
        print(f"Keys checked: {format_int(keys_checked)}")
        print(f"Time elapsed: {get_human_readable_time(elapsed_time)}")
        print(f"Speed: {format_int(keys_checked/elapsed_time)} keys/second")
        
    except Exception as e:
        print(f"\nError in main search loop: {str(e)}")
        import traceback
        traceback.print_exc()
    
    return None

if __name__ == "__main__":
    main()
