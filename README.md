# DIS Password Manager

A simple password manager written in Python using [Flask](https://palletsprojects.com/p/flask/), [bcrypt](https://pypi.org/project/bcrypt/), and [cryptography](https://pypi.org/project/cryptography/). The application supports:

- User registration and login.
- Storing, uploading, searching, viewing, and removing passwords.
- Checking password strength.
- Encrypting passwords with a key from `key.key`.

## Project Structure

- [main.py](main.py) – Bootstraps the Flask application.
- [user_manager.py](user_manager.py) – Manages user registration, login, and data storage.
- [user.py](user.py) – Defines a `User` class that interacts with the password manager.
- [password_manager.py](password_manager.py) – Performs password storage, encryption/decryption, and strength checking.
- [requirements.txt](requirements.txt) – Lists Python dependencies.
- `templates/` – Contains HTML templates for the Flask routes (home, login, register, dashboard, navigation, upload).
- `passwords/` – Stores user-specific JSON files with encrypted passwords.
- [users.csv](users.csv) – Stores hashed user credentials.

## Installation and Setup

1. **Clone the repository:**

   ```sh
   git clone https://github.com/JavienTJE/DIS
   cd DIS
   ```

2. **Install dependencies:**

   ```sh
   pip install -r requirements.txt
   ```

3. **(Optional) Update the secret key:**

   If needed, update the secret key in main.py.

4. **Run the Flask application:**

   Either run:

   ```sh
   python main.py
   ```

   or use the VS Code debugger by selecting **Python Debugger: Flask**.

5. **Open your browser:**

   Navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000).

## Usage

1. **Register a New User:**

   Open the **Register** page and create a new account.

2. **Log In and Manage Passwords:**

   After logging in via the **Login** page, use the **Dashboard** to:
   - **Add Passwords:** Securely store credentials.
   - **Generate Passwords:** Create strong passwords for new accounts.
   - **View Passwords:** Retrieve and check the strength of stored passwords.
   - **Remove Passwords:** Delete credentials as needed.
   - **Search Passwords:** Find specific credentials.

3. **Encryption:**

   Passwords are encrypted using the key in `key.key`.

## Additional Information

- Passwords are saved in the passwords directory as JSON files (e.g. `a_passwords.json`, `test_passwords.json`, etc.) that are managed by the `password_manager.py`.
- For user data handling, refer to the logic in `user_manager.py` and `user.py`.

## Contributing

If you encounter issues or wish to contribute, please open an issue or contact the project maintainers.

Enjoy using DIS Password Manager!