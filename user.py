from datetime import datetime
import bcrypt  # Used for hashing and verifying passwords
from password_manager import PasswordManager  # Manages user password operations


class User:
    """
    Represents a user with a username and hashed password
    """

    def __init__(
        self, username, password, date, is_hashed=False
    ):  # Initialize a user with username and password
        self.username = username  # Assign username
        if is_hashed:
            self.password = password.encode("utf-8")  # Use the given hashed password
        else:
            self.password = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            )  # Create a hashed password
        self.change_password_time = date
        self.password_manager = PasswordManager(
            self.username
        )  # Instantiate a PasswordManager for this user

    def check_password(self, password):
        """
        Verifies a provided password against the stored hash
        """
        return bcrypt.checkpw(
            password.encode("utf-8"), self.password
        )  # Compare provided password with stored hash
    
    def change_password(self, new_password):
        """
        Changes the password of the user
        """
        self.password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
        self.change_password_time = datetime.now()