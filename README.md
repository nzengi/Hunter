# GPU-Accelerated Bitcoin Private Key Finder

A high-performance tool designed to search for Bitcoin private keys within a specific range, targeting addresses with specific patterns.

## Overview

This tool searches for Bitcoin private keys that generate addresses with specific characteristics:
- Within the range `0x1000000000000000000` to `0x1ffffffffffffffffff`
- Addresses starting with `12VV` and ending with `ysn4`
- Target address: `12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4`
- Public Key Hash: `105b7f253f0ebd7843adaebbd805c944bfb863e4`

## Features

- GPU-accelerated cryptographic operations using CUDA
- Efficient parallelized search algorithm
- Real-time statistics and progress tracking
- Save matching keys to a file for later analysis
- Optimized for NVIDIA GPUs (tested on NVIDIA 3060)

## Requirements

- NVIDIA GPU with CUDA support
- Python 3.6+
- PyCUDA
- NumPy
- coincurve
- base58

## Installation

1. Install CUDA Toolkit (corresponding to your GPU):
   ```
   # Visit https://developer.nvidia.com/cuda-downloads to get the appropriate version
   ```

2. Install Python dependencies:
   ```
   pip install pycuda numpy coincurve base58
   ```

## Usage

Run the program with default settings:

```bash
python bitcoin_puzzle_solver.py
