import os
import sys
import getpass
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
from colorama import Fore, Style, init

init(autoreset=True)

NOTES_DIR = 'notes_files'
SALT = b'\x00\x01\x02\x03\x04\x05\x06\x07'  # Fixed salt for key derivation


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_note(note: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(note.encode())


def decrypt_note(token: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token).decode()


def print_menu():
    print(Fore.YELLOW + '=' * 20 + ' \U0001F512 Welcome to SecurePad ' + '=' * 20)
    print(Fore.MAGENTA + f"\n[1] {Fore.WHITE}Write a New Encrypted Note")
    print(f"{Fore.MAGENTA}[2] {Fore.WHITE}View a Encrypted Note")
    print(f"{Fore.MAGENTA}[3] {Fore.WHITE}Exit\n")


def write_note():
    note = input(Fore.CYAN + 'Note: ')
    password = getpass.getpass(Fore.YELLOW + 'Enter a password to encrypt this note: ')
    key = derive_key(password, SALT)
    encrypted = encrypt_note(note, key)
    if not os.path.exists(NOTES_DIR):
        os.makedirs(NOTES_DIR)
    filename = f"note_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    filepath = os.path.join(NOTES_DIR, filename)
    with open(filepath, 'wb') as f:
        f.write(encrypted)
    print(Fore.GREEN + f"\nNote saved as {filename}!\n")


def list_notes():
    if not os.path.exists(NOTES_DIR):
        return []
    files = [f for f in os.listdir(NOTES_DIR) if f.startswith('note_') and f.endswith('.txt')]
    files.sort()
    return files


def view_note():
    files = list_notes()
    if not files:
        print(Fore.RED + 'No notes to view.')
        return
    print(Fore.WHITE + '\nNo.  Filename')
    print(Fore.WHITE + '--------------------------')
    for idx, fname in enumerate(files, 1):
        print(f"{Fore.CYAN}{idx}{Fore.WHITE}.  {fname}")
    try:
        choice = int(input(Fore.YELLOW + '\nEnter note number [1]: ') or '1')
        if not (1 <= choice <= len(files)):
            print(Fore.RED + 'Invalid choice.')
            return
    except ValueError:
        print(Fore.RED + 'Invalid input.')
        return
    filename = files[choice - 1]
    password = getpass.getpass(Fore.YELLOW + 'Enter the password to decrypt this note: ')
    key = derive_key(password, SALT)
    filepath = os.path.join(NOTES_DIR, filename)
    with open(filepath, 'rb') as f:
        encrypted = f.read()
        try:
            note = decrypt_note(encrypted, key)
            print(Fore.GREEN + f"\n\U0001F512 {filename}\n" + Fore.CYAN + note + '\n')
        except Exception:
            print(Fore.RED + 'Failed to decrypt note. Wrong password or corrupted file.')


def main():
    while True:
        print_menu()
        option = input(Fore.YELLOW + 'Select an option [1/2/3]: ').strip()
        if option == '1':
            write_note()
        elif option == '2':
            view_note()
        elif option == '3':
            print(Fore.MAGENTA + 'Goodbye!')
            sys.exit(0)
        else:
            print(Fore.RED + 'Invalid option. Please try again.')

if __name__ == '__main__':
    main() 