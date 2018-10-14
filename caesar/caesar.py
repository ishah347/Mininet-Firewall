from cs50 import get_string
from sys import argv, exit


def main():
    # Return an error message and exit if length of argv isn't 2
    if len(argv) != 2:
        print('Usage: python caesar.py key')
        exit(1)
    # Recognize key
    key = int(argv[1])
    # Return an error message and exit if key is negative
    if key < 0:
        print('Key needs to be a non-negative integer')
        exit(2)
    # Prompt user for plaintext
    plaintext = get_string('plaintext: ')
    # Encrypt plaintext and make ciphertext
    print('ciphertext: ', end='')
    for i in plaintext:
        # Maintain uppercase form for letters and apply key
        if i.isupper():
            print(chr(((ord(i) - ord('A') + key) % 26) + ord('A')), end='')
        # Maintain lowercase form for letters and apply key
        elif i.islower():
            print(chr(((ord(i) - ord('a') + key) % 26) + ord('a')), end='')
        # Return all other characters as they are
        else:
            print(i, end='')
    # Return line
    print()


if __name__ == '__main__':
    main()
