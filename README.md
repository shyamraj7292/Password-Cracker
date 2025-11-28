# Password Cracker

A Python-based tool that attempts to crack hashed passwords using either a wordlist (dictionary attack) or brute-force techniques with multi-threading support.

## Overview

This project demonstrates how attackers attempt to break hashed passwords using dictionary attacks and brute-force methods. The script allows users to input a hash, specify a hash algorithm (e.g., MD5, SHA-256), and choose between using a wordlist or generating passwords dynamically.

## Features

- **Multiple Hash Algorithms**: Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512
- **Dictionary Attack**: Uses wordlists to crack passwords
- **Brute-Force Attack**: Generates password combinations with customizable character sets and length ranges
- **Multi-Threading**: Utilizes multiple threads to speed up the cracking process
- **Performance Statistics**: Shows attempts made, time elapsed, and hashes per second
- **Flexible Configuration**: Customizable character sets, length ranges, and thread count

## Requirements

All required libraries are part of Python's standard library:
- `hashlib` - Cryptographic hash functions
- `argparse` - Command-line argument parsing
- `itertools` - Efficient iteration tools
- `threading` - Multi-threading support
- `queue` - Thread-safe queue implementation

**Python Version**: 3.6+

## Installation

1. Clone or download this repository
2. No additional packages need to be installed (all dependencies are in Python standard library)

```bash
git clone <repository-url>
cd Password-Cracker
```

## Usage

### Basic Syntax

```bash
python password_cracker.py -H <hash> -t <hash_type> [OPTIONS]
```

### Options

| Option | Description | Required |
|--------|-------------|----------|
| `-H, --hash` | Target hash to crack | Yes |
| `-t, --hash-type` | Hash algorithm (md5, sha1, sha224, sha256, sha384, sha512) | Yes |
| `-w, --wordlist` | Path to wordlist file (for dictionary attack) | Conditional* |
| `-b, --brute-force` | Use brute-force attack | Conditional* |
| `--min-length` | Minimum password length for brute-force (default: 1) | No |
| `--max-length` | Maximum password length for brute-force (default: 4) | No |
| `--charset` | Custom character set for brute-force | No |
| `--charset-preset` | Preset character set (lower, upper, digits, alphanumeric, all) | No |
| `--threads` | Number of threads to use (default: 4) | No |

*Either `--wordlist` or `--brute-force` must be specified.

### Examples

#### Dictionary Attack

Crack an MD5 hash using a wordlist:

```bash
python password_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w wordlist.txt
```

Crack a SHA-256 hash using a wordlist:

```bash
python password_cracker.py -H 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 -t sha256 -w wordlist.txt
```

#### Brute-Force Attack

Crack a password with length 4-6 using lowercase letters and digits:

```bash
python password_cracker.py -H <hash> -t sha256 -b --min-length 4 --max-length 6
```

Brute-force with custom character set:

```bash
python password_cracker.py -H <hash> -t md5 -b --min-length 3 --max-length 4 --charset abc123
```

Brute-force with preset character set (all alphanumeric):

```bash
python password_cracker.py -H <hash> -t md5 -b --min-length 1 --max-length 4 --charset-preset alphanumeric
```

Brute-force with all characters (including special):

```bash
python password_cracker.py -H <hash> -t md5 -b --min-length 1 --max-length 3 --charset-preset all --threads 8
```

## How It Works

### 1. Input Handling
The user provides:
- A hashed password
- Hash type (algorithm)
- Attack method (dictionary or brute-force)
- Optional parameters (wordlist, password length range, character set, threads)

### 2. Dictionary Attack
- Reads words from a wordlist file
- Hashes each word and its variations (lowercase, uppercase, capitalized)
- Compares hashes with the target hash
- Uses multiple threads to process words in parallel

### 3. Brute-Force Attack
- Generates password combinations using specified character set
- Iterates through all possible combinations within the length range
- Hashes each generated password
- Compares hashes with the target hash
- Uses multiple threads to process password attempts in parallel

### 4. Multi-Threading
- Divides work among multiple threads
- Each thread processes a batch of passwords independently
- Thread-safe mechanisms ensure correct result reporting
- Significantly improves performance on multi-core systems

### 5. Output Result
- If a match is found: displays the cracked password
- If not found: reports failure with statistics
- Always shows performance metrics (attempts, time, speed)

## Creating Test Hashes

You can create test hashes using Python:

```python
import hashlib

# MD5 example
password = "password"
hash_obj = hashlib.md5(password.encode())
print(f"MD5: {hash_obj.hexdigest()}")

# SHA-256 example
hash_obj = hashlib.sha256(password.encode())
print(f"SHA-256: {hash_obj.hexdigest()}")
```

Or using command line:

**Linux/Mac:**
```bash
echo -n "password" | md5sum
echo -n "password" | sha256sum
```

**Windows PowerShell:**
```powershell
"password" | ForEach-Object {[System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($_)) | ForEach-Object {$_.ToString("x2")} }
```

## Sample Wordlist

A sample wordlist (`sample_wordlist.txt`) is included for testing. You can also download larger wordlists from:
- [SecLists](https://github.com/danielmiessler/SecLists)
- [RockYou](https://www.kaggle.com/datasets/wjburns/common-password-list-rockyoutxt)

## Key Concepts Covered

- **Cryptographic Hash Functions**: Understanding how MD5, SHA-256, etc. work
- **Dictionary Attacks**: Using wordlists to crack passwords
- **Brute-Force Techniques**: Generating and testing password combinations
- **Multi-Threading**: Parallel processing for performance optimization
- **Command-Line Arguments**: Handling user inputs via argparse
- **Thread Safety**: Using locks and queues for concurrent operations

## Performance Tips

1. **Use Dictionary Attacks First**: They're much faster for common passwords
2. **Optimize Thread Count**: Match thread count to CPU cores (typically 4-8 threads)
3. **Limit Brute-Force Length**: Longer passwords exponentially increase time
4. **Use Appropriate Character Sets**: Smaller character sets are faster
5. **Start Small**: Test with shorter length ranges first

## Limitations

- Brute-force attacks become exponentially slower with longer passwords
- Dictionary attacks only work if the password is in the wordlist
- Very long or complex passwords may take impractical amounts of time
- This tool is for educational purposes and authorized testing only

## Security Notes

⚠️ **Important**: This tool is intended for:
- Educational purposes
- Security research
- Authorized penetration testing
- Testing your own systems

**Never use this tool to attempt to crack passwords without explicit authorization.** Unauthorized access attempts are illegal.

## Project Structure

```
Password-Cracker/
├── password_cracker.py      # Main password cracker script
├── requirements.txt         # Python dependencies (none needed)
├── README.md               # This file
└── sample_wordlist.txt     # Sample wordlist for testing
```

## Troubleshooting

### Issue: "Wordlist file not found"
- Check that the file path is correct
- Use absolute path if relative path doesn't work

### Issue: "Password not found"
- Try a different wordlist
- Increase brute-force length range
- Verify the hash is correct
- Check that you're using the correct hash algorithm

### Issue: Slow performance
- Increase thread count (up to your CPU core count)
- Reduce brute-force length range
- Use smaller character set
- Try dictionary attack first

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

## License

This project is for educational purposes. Use responsibly and only with authorization.

## Author

Created as part of a cybersecurity/computer science educational project.
