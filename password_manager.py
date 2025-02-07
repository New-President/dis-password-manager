import random
import json
import os
from cryptography.fernet import Fernet
import requests
import hashlib


class PasswordManager:
    """
    Manages password operations for a user
    """

    def __init__(self, master_username):
        self.master_username = master_username  # Stores the master username
        self.stored_passwords = {}  # Holds service passwords in a dictionary

        try:
            # Reads existing encryption key.
            with open("key.key", "rb") as key_file:
                self.key = key_file.read()
        except FileNotFoundError:
            self.key = (
                Fernet.generate_key()
            )  # Generates a new encryption key if not found
            with open("key.key", "wb") as key_file:
                key_file.write(self.key)

        try:
            merged_path = os.path.join("passwords", f"{master_username}_passwords.json")
            self.load_passwords(
                merged_path
            )  # Attempts to load existing data from a json file
        except FileNotFoundError:
            print("No existing password file found. (1)\n")

    def add_password(self, service_name, username, password):
        """
        Adds a new service with associated username/password
        """
        self.stored_passwords[service_name] = [
            username,
            self.encrypt_password(password),
        ]
        print(f"\nPassword and username for '{service_name}' added successfully!\n")

    def get_passwords(self):
        """
        Returns a list of tuples with service name and its decrypted password
        """
        return [
            (service, self.decrypt_password(password[1]))
            for service, password in self.stored_passwords.items()
        ]

    def get_password(self, service_name):
        """
        Fetches specific decrypted password for a given service
        """
        try:
            return self.decrypt_password(self.stored_passwords[service_name][1])
        except KeyError:
            return None

    def get_service_username(self, service_name):
        """
        Retrieves stored username for a given service
        """
        try:
            return self.stored_passwords[service_name][0]
        except KeyError:
            return None

    def remove_password(self, service_name):
        """Removes a stored service entry"""
        try:
            self.stored_passwords.pop(service_name)
            print(
                f"\nPassword and username for '{service_name}' removed successfully!\n"
            )
        except KeyError:
            print(f"\nNo password stored for '{service_name}'.\n")

    def change_service_name(self, old_service_name, new_service_name):
        """Changes a service name"""
        try:
            self.stored_passwords[new_service_name] = self.stored_passwords.pop(
                old_service_name
            )
        except KeyError:
            print("Service not found.")

    def change_service_username(self, service_name, new_service_username):
        """Changes a service's username"""
        try:
            self.stored_passwords[service_name][0] = new_service_username
        except KeyError:
            print("Service not found.")

    def change_service_password(self, service_name, new_service_password):
        """Changes a password for a service"""
        try:
            self.stored_passwords[service_name][1] = self.encrypt_password(
                new_service_password
            )
        except KeyError:
            print("\nPassword not found.\n")

    def view_passwords(self):
        """
        Prints out all stored passwords with strength
        """
        if not self.stored_passwords:
            print("\nNo passwords stored yet.\n")
            return

        print("\nService: Username | Password")
        for service, password_data in self.stored_passwords.items():
            decrypted_pwd = self.decrypt_password(
                password_data[1]
            )  # Decrypt stored password
            strength = self.check_password_strength(
                decrypted_pwd
            )  # Evaluate password strength
            print(f"- {service}: {password_data[0]} | {decrypted_pwd} {strength}")
        print()

    def generate_password(self):
        """
        Generates a password with at least one of each listed character type
        """
        ascii_lowercase = "abcdefghijklmnopqrstuvwxyz"
        ascii_uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        punctuation = "!" + '"' + "#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
        printable_chars = digits + ascii_lowercase + ascii_uppercase + punctuation

        password_chars = []
        password_chars.append(random.choice(ascii_lowercase))
        password_chars.append(random.choice(ascii_uppercase))
        password_chars.append(random.choice(digits))
        password_chars.append(random.choice(punctuation))

        for _ in range(12):
            password_chars.append(random.choice(printable_chars))

        return "".join(password_chars)

    def save_passwords(self, file_path):
        """
        Saves current passwords to a JSON file
        """
        with open(file_path, "w", encoding="utf-8") as file_obj:
            json.dump(self.stored_passwords, file_obj)

    def load_passwords(self, file_path):
        """
        Loads password data from a JSON file
        """
        try:
            with open(file_path, "r", encoding="utf-8") as file_obj:
                self.stored_passwords = json.load(file_obj)
        except FileNotFoundError:
            print("No existing password file found. (2)")

    def append_passwords(self, file_path):
        """
        Appends password data from uploaded password file
        """
        appended_passwords = {}
        try:
            with open(file_path, "r", encoding="utf-8") as file_obj:
                appended_passwords = json.load(file_obj)
            self.stored_passwords.update(
                appended_passwords
            )  # Parses uploaded json file and appends content to the current stored passwords.

        except FileNotFoundError:
            print("No existing password file found. (3)")

    def encrypt_password(self, password):
        """
        Encrypts a password using the Fernet symmetric encryption algorithm
        """
        cipher = Fernet(self.key)
        return cipher.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_text):
        """
        Decrypts an encrypted password using the Fernet symmetric encryption algorithm
        """
        cipher = Fernet(self.key)
        return cipher.decrypt(encrypted_text.encode()).decode()

    def check_password_strength(self, password):
        """
        Checks password strength based on length, case, digits, and punctuation
        """
        score = 0
        if len(password) >= 8:
            score += 1
        if any(char.isupper() for char in password) and any(
            char.islower() for char in password
        ):
            score += 1
        if any(char.isdigit() for char in password):
            score += 1
        if any(not char.isalnum() for char in password):
            score += 1
        if score == 4:
            return "Strong"
        if score >= 2:
            return "Moderate"
        return "Weak"

    def check_pwned_password(self, password):
        """
        Checks if a password has been pwned
        """
        sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        first5 = sha1password[:5]
        tail = sha1password[5:]
        url = f"https://api.pwnedpasswords.com/range/{first5}"
        response = requests.get(url)
        if response.status_code != 200:
            raise RuntimeError(f"Error fetching: {response.status_code}")

        hashes = (line.split(":") for line in response.text.splitlines())
        for hash, count in hashes:
            if hash == tail:
                return int(count)
        return 0
