# Usage Examples

Quick reference guide for using the Password Cracker tool.

## Quick Start

### 1. Dictionary Attack (Recommended First)

Try cracking a hash using a wordlist:

```bash
python password_cracker.py -H <hash> -t md5 -w sample_wordlist.txt
```

### 2. Brute-Force Attack

If dictionary attack fails, try brute-force:

```bash
python password_cracker.py -H <hash> -t sha256 -b --min-length 1 --max-length 4
```

## Common Hash Values for Testing

Here are some common password hashes you can use for testing:

### MD5 Hashes

- `password` → `5f4dcc3b5aa765d61d8327deb882cf99`
- `test` → `098f6bcd4621d373cade4e832627b4f6`
- `admin` → `21232f297a57a5a743894a0e4a801fc3`
- `123456` → `e10adc3949ba59abbe56e057f20f883e`

### SHA-256 Hashes

- `password` → `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8`
- `test` → `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`
- `admin` → `8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918`

## Example Commands

### Example 1: Dictionary Attack with MD5

```bash
python password_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w sample_wordlist.txt
```

**Expected Output:**
```
[*] Target hash: 5f4dcc3b5aa765d61d8327deb882cf99
[*] Hash type: MD5
[*] Threads: 4

[*] Loaded 69 words from wordlist
[*] Starting dictionary attack with 4 threads...

[+] SUCCESS! Password found: password
```

### Example 2: Brute-Force Short Password

```bash
python password_cracker.py -H 098f6bcd4621d373cade4e832627b4f6 -t md5 -b --min-length 3 --max-length 5 --charset-preset lower
```

### Example 3: Brute-Force with Numbers Only

```bash
python password_cracker.py -H <hash> -t md5 -b --min-length 1 --max-length 6 --charset-preset digits
```

### Example 4: Brute-Force with Custom Character Set

```bash
python password_cracker.py -H <hash> -t sha256 -b --min-length 2 --max-length 4 --charset abc123
```

### Example 5: High-Performance Brute-Force

Use more threads for faster cracking (adjust based on your CPU):

```bash
python password_cracker.py -H <hash> -t md5 -b --min-length 1 --max-length 4 --charset-preset alphanumeric --threads 8
```

## Generating Test Hashes

### Using Python

```python
import hashlib

password = "your_password_here"

# MD5
print(f"MD5: {hashlib.md5(password.encode()).hexdigest()}")

# SHA-256
print(f"SHA-256: {hashlib.sha256(password.encode()).hexdigest()}")

# SHA-512
print(f"SHA-512: {hashlib.sha512(password.encode()).hexdigest()}")
```

### Using Command Line (Linux/Mac)

```bash
echo -n "password" | md5sum
echo -n "password" | sha256sum
```

### Using PowerShell (Windows)

```powershell
# MD5
$md5 = [System.Security.Cryptography.MD5]::Create()
$hash = [System.BitConverter]::ToString($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("password"))).Replace("-", "").ToLower()
Write-Host "MD5: $hash"

# SHA-256
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hash = [System.BitConverter]::ToString($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("password"))).Replace("-", "").ToLower()
Write-Host "SHA-256: $hash"
```

## Tips for Effective Cracking

1. **Start with Dictionary Attack**: Always try dictionary attack first - it's much faster
2. **Use Appropriate Wordlists**: Larger wordlists increase chances but take more time
3. **Limit Brute-Force Range**: Start with shorter lengths (1-4) and increase gradually
4. **Optimize Character Sets**: Use smaller character sets when possible (e.g., digits only for PINs)
5. **Adjust Threads**: Match thread count to your CPU cores for best performance
6. **Be Patient**: Longer passwords take exponentially more time

## Troubleshooting

**Problem**: "Password not found"
- Verify the hash is correct
- Check that you're using the right hash algorithm
- Try a different wordlist
- Increase brute-force length range

**Problem**: Too slow
- Reduce maximum length
- Use smaller character set
- Increase thread count (up to CPU core count)
- Try dictionary attack instead

**Problem**: "Wordlist file not found"
- Check the file path is correct
- Use absolute path: `C:\full\path\to\wordlist.txt`

