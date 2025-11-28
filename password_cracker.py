#!/usr/bin/env python3
"""
Password Cracker Tool

A Python-based tool that attempts to crack hashed passwords using either
a wordlist (dictionary attack) or brute-force techniques with multi-threading support.
"""

import hashlib
import argparse
import itertools
import threading
import queue
import sys
import time
from typing import Optional, Callable, Set


class PasswordCracker:
    """Main class for password cracking operations."""
    
    # Supported hash algorithms
    HASH_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
    }
    
    # Default character sets for brute-force attacks
    LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
    UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    DIGITS = '0123456789'
    SPECIAL = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    def __init__(self, target_hash: str, hash_type: str, num_threads: int = 4):
        """
        Initialize the PasswordCracker.
        
        Args:
            target_hash: The hash to crack
            hash_type: Type of hash algorithm (md5, sha256, etc.)
            num_threads: Number of threads to use for cracking
        """
        self.target_hash = target_hash.lower()
        self.hash_type = hash_type.lower()
        self.num_threads = num_threads
        self.found = False
        self.result = None
        self.lock = threading.Lock()
        self.attempts = 0
        self.start_time = None
        
        if self.hash_type not in self.HASH_ALGORITHMS:
            raise ValueError(f"Unsupported hash type: {hash_type}. "
                           f"Supported types: {', '.join(self.HASH_ALGORITHMS.keys())}")
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using the specified algorithm.
        
        Args:
            password: The password to hash
            
        Returns:
            Hexadecimal hash string
        """
        hash_func = self.HASH_ALGORITHMS[self.hash_type]
        return hash_func(password.encode()).hexdigest()
    
    def check_password(self, password: str) -> bool:
        """
        Check if a password matches the target hash.
        
        Args:
            password: The password to check
            
        Returns:
            True if the password matches, False otherwise
        """
        with self.lock:
            self.attempts += 1
        
        hashed = self.hash_password(password)
        if hashed == self.target_hash:
            with self.lock:
                if not self.found:
                    self.found = True
                    self.result = password
            return True
        return False
    
    def dictionary_attack(self, wordlist_path: str) -> Optional[str]:
        """
        Perform a dictionary attack using a wordlist file.
        
        Args:
            wordlist_path: Path to the wordlist file
            
        Returns:
            The cracked password if found, None otherwise
        """
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: Wordlist file '{wordlist_path}' not found.")
            return None
        except Exception as e:
            print(f"Error reading wordlist: {e}")
            return None
        
        if not words:
            print("Error: Wordlist is empty.")
            return None
        
        print(f"[*] Loaded {len(words)} words from wordlist")
        print(f"[*] Starting dictionary attack with {self.num_threads} threads...")
        
        self.start_time = time.time()
        word_queue = queue.Queue()
        
        # Add words to queue
        for word in words:
            if self.found:
                break
            word_queue.put(word)
        
        def worker():
            """Worker thread for dictionary attack."""
            while not self.found and not word_queue.empty():
                try:
                    word = word_queue.get(timeout=1)
                    # Try original word
                    if self.check_password(word):
                        return
                    # Try lowercase
                    if word.lower() != word and self.check_password(word.lower()):
                        return
                    # Try uppercase
                    if word.upper() != word and self.check_password(word.upper()):
                        return
                    # Try capitalized
                    if word.capitalize() != word and self.check_password(word.capitalize()):
                        return
                    word_queue.task_done()
                except queue.Empty:
                    break
        
        # Start worker threads
        threads = []
        for _ in range(min(self.num_threads, len(words))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for threads to complete
        for t in threads:
            t.join()
        
        return self.result
    
    def brute_force_attack(self, min_length: int, max_length: int, 
                          charset: str = None) -> Optional[str]:
        """
        Perform a brute-force attack.
        
        Args:
            min_length: Minimum password length
            max_length: Maximum password length
            charset: Character set to use (default: lowercase + digits)
            
        Returns:
            The cracked password if found, None otherwise
        """
        if charset is None:
            charset = self.LOWERCASE + self.DIGITS
        
        if min_length < 1:
            min_length = 1
        if max_length < min_length:
            max_length = min_length
        
        print(f"[*] Starting brute-force attack...")
        print(f"[*] Length range: {min_length}-{max_length}")
        print(f"[*] Character set: {charset[:50]}{'...' if len(charset) > 50 else ''} ({len(charset)} characters)")
        print(f"[*] Using {self.num_threads} threads...")
        
        self.start_time = time.time()
        
        # Process each length separately for better distribution
        for length in range(min_length, max_length + 1):
            if self.found:
                break
            
            total_combinations = len(charset) ** length
            print(f"[*] Trying length {length} ({total_combinations:,} combinations)...")
            
            # Generate passwords for this length using a queue-based approach
            chunk_size = 1000  # Process passwords in chunks
            password_queue = queue.Queue()
            password_iter = itertools.product(charset, repeat=length)
            iter_lock = threading.Lock()
            
            # Generator function to safely get next batch from iterator
            def get_next_batch():
                """Safely get next batch of passwords from iterator."""
                with iter_lock:
                    batch = []
                    try:
                        for _ in range(chunk_size):
                            password = ''.join(next(password_iter))
                            batch.append(password)
                    except StopIteration:
                        pass
                    return batch
            
            def worker():
                """Worker thread for brute-force attack."""
                while not self.found:
                    # Get a batch of passwords to try
                    passwords = get_next_batch()
                    
                    if not passwords:
                        break
                    
                    # Check each password in the batch
                    for password in passwords:
                        if self.found:
                            return
                        if self.check_password(password):
                            return
            
            # Start worker threads
            threads = []
            for _ in range(self.num_threads):
                t = threading.Thread(target=worker, daemon=True)
                t.start()
                threads.append(t)
            
            # Wait for threads to complete
            for t in threads:
                t.join()
            
            if self.found:
                break
        
        return self.result
    
    def print_stats(self):
        """Print statistics about the cracking attempt."""
        if self.start_time:
            elapsed = time.time() - self.start_time
            print(f"\n[*] Attempts made: {self.attempts:,}")
            print(f"[*] Time elapsed: {elapsed:.2f} seconds")
            if elapsed > 0:
                print(f"[*] Speed: {self.attempts / elapsed:,.0f} hashes/second")


def main():
    """Main function to handle command-line arguments and execute attacks."""
    parser = argparse.ArgumentParser(
        description='Password Cracker - Crack hashed passwords using dictionary or brute-force attacks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dictionary attack with MD5 hash
  python password_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w wordlist.txt
  
  # Brute-force attack with SHA-256 hash (length 4-6, lowercase + digits)
  python password_cracker.py -H 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 -t sha256 -b --min-length 4 --max-length 6
  
  # Brute-force with custom character set
  python password_cracker.py -H <hash> -t md5 -b --min-length 3 --max-length 4 --charset abc123
        """
    )
    
    parser.add_argument('-H', '--hash', required=True,
                       help='Target hash to crack')
    parser.add_argument('-t', '--hash-type', required=True,
                       choices=list(PasswordCracker.HASH_ALGORITHMS.keys()),
                       help='Hash algorithm type')
    parser.add_argument('-w', '--wordlist',
                       help='Path to wordlist file (for dictionary attack)')
    parser.add_argument('-b', '--brute-force', action='store_true',
                       help='Use brute-force attack instead of dictionary')
    parser.add_argument('--min-length', type=int, default=1,
                       help='Minimum password length for brute-force (default: 1)')
    parser.add_argument('--max-length', type=int, default=4,
                       help='Maximum password length for brute-force (default: 4)')
    parser.add_argument('--charset', type=str,
                       help='Custom character set for brute-force (default: lowercase + digits)')
    parser.add_argument('--threads', type=int, default=4,
                       help='Number of threads to use (default: 4)')
    parser.add_argument('--charset-preset', choices=['lower', 'upper', 'digits', 'alphanumeric', 'all'],
                       help='Preset character set for brute-force')
    
    args = parser.parse_args()
    
    # Determine character set
    charset = None
    if args.charset:
        charset = args.charset
    elif args.charset_preset:
        cracker = PasswordCracker('', args.hash_type)
        presets = {
            'lower': cracker.LOWERCASE,
            'upper': cracker.UPPERCASE,
            'digits': cracker.DIGITS,
            'alphanumeric': cracker.LOWERCASE + cracker.UPPERCASE + cracker.DIGITS,
            'all': cracker.LOWERCASE + cracker.UPPERCASE + cracker.DIGITS + cracker.SPECIAL
        }
        charset = presets[args.charset_preset]
    
    # Validate arguments
    if not args.wordlist and not args.brute_force:
        print("Error: Must specify either --wordlist or --brute-force")
        parser.print_help()
        sys.exit(1)
    
    if args.brute_force and args.wordlist:
        print("Warning: Both wordlist and brute-force specified. Using wordlist.")
        args.brute_force = False
    
    try:
        # Create cracker instance
        cracker = PasswordCracker(args.hash, args.hash_type, args.threads)
        
        print(f"[*] Target hash: {args.hash}")
        print(f"[*] Hash type: {args.hash_type.upper()}")
        print(f"[*] Threads: {args.threads}\n")
        
        result = None
        
        # Perform attack
        if args.wordlist:
            result = cracker.dictionary_attack(args.wordlist)
        elif args.brute_force:
            result = cracker.brute_force_attack(args.min_length, args.max_length, charset)
        
        # Print results
        cracker.print_stats()
        
        if result:
            print(f"\n[+] SUCCESS! Password found: {result}")
            sys.exit(0)
        else:
            print(f"\n[-] Password not found in the given constraints.")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

