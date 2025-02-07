import csv
from user import User


class UserManager:
    """
    Manages user operations for the password manager
    """
    def __init__(self):
        self.users = []
        try:
            self.load_users("users.csv")
        except FileNotFoundError:
            pass

    def add_user(self, username, password, date):
        """
        Adds a new user to the user list
        """
        if self.find_user(username):
            print("\nUsername already exists. Please choose a different username.\n")
            return False
        user = User(username, password, date, is_hashed=False)
        self.users.append(user)

        print("\nUser registered successfully!\n")
        return True

    def find_user(self, username):
        """
        Finds a user by username
        """
        for user in self.users:
            if user.username == username:
                return user
        return None

    def login(self, username, password):
        """
        Logs in a user if the username and password match
        """
        user = self.find_user(username)
        if user and user.check_password(password):
            return user
        return False

    def save_users(self, file):
        """
        Saves all users to a csv file.
        """
        with open(file, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for user in self.users:
                writer.writerow(
                    [
                        user.username,
                        user.password.decode("utf-8"),
                        user.change_password_time,
                    ]
                )

    def load_users(self, file):
        """
        Reads off a csv file and loads in user accounts contained in the file.
        """
        with open(file, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                self.users.append(User(row[0], row[1], row[2], is_hashed=True))

    def check_password_strength(self, password):
        """
        Checks the strength of a password for a single service.
        """
        if len(password) < 8:
            return False
        if not any(char.isdigit() for char in password):
            return False
        if not any(char.isupper() for char in password) or not any(
            char.islower() for char in password
        ):
            return False
        if not any(char.isdigit() for char in password):
            return False
        return True
