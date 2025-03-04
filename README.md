# Kyber-512 Post-Quantum Cryptography Implementation

A Python implementation of the Kyber-512 post-quantum key encapsulation mechanism (KEM) using SageMath. This implementation includes both the core cryptographic operations and a simple client-server demonstration of key exchange.

## Overview

Kyber is a lattice-based key encapsulation mechanism that is designed to be secure against both classical and quantum computers. This implementation focuses on Kyber-512, which provides NIST security level 1 (equivalent to AES-128).

## Features

- Complete Kyber-512 implementation including:
  - Key generation
  - Encryption/decryption
  - CCA-secure KEM operations
  - Number Theoretic Transform (NTT) operations
  - Compression/decompression functions
- Client-server demonstration of key exchange
- Test suite in Jupyter notebook format

## Prerequisites

- Python 3.9+
- SageMath 9.7+
- Required Python packages:
  - socket
  - pickle
  - struct
  - hashlib
  - secrets

## Installation

1. Clone the repository:
```bash
git clone https://github.com/JvThunder/kyber-sage.git
cd kyber-sage
```

2. Ensure SageMath is installed and accessible:
```bash
source activate sage
```

## Usage

### Check out the code implementation in Sage:
```bash
sage kyber.sage
```

### Running the Key Exchange Demo

1. Start the server:
```bash
python -u server.py
```

2. In a separate terminal, run the client:
```bash
python -u client.py
```

3. You can also run the notebook file to see the implementation in action:
```bash
jupyter notebook kyber_test.ipynb
```

## Implementation Details

### Parameters

- n = 512 (polynomial degree)
- q = 3329 (modulus)
- k = 2 (polynomial vector dimension)
- η₁ = 3 (noise parameter)
- η₂ = 2 (noise parameter)
- du = 10 (compression parameter)
- dv = 4 (compression parameter)

## File Structure

- `kyber.sage` - Source implementation in SageMath
- `kyber.py` - Auto-generated Python version
- `client.py` - Client implementation for key exchange
- `server.py` - Server implementation for key exchange
- `kyber_test.ipynb` - Test suite
- `commands.md` - Running instructions

## Contributing
This repo is made by **Joshua Adrian Cahyono** [@JvThunder](https://github.com/JvThunder) and **Jeremy Nathan Jusuf** [@JeremyNathanJusuf](https://github.com/JeremyNathanJusuf)

Contributions are welcome! Please feel free to submit a Pull Request.

## References

- [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)

## Disclaimer

This implementation is for educational purposes and should not be used in production without proper security review.