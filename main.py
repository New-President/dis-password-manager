import os
import json
from datetime import datetime
from datetime import timedelta
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory,
)
from werkzeug.utils import secure_filename
from user_manager import UserManager

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Replace with a strong, unique secret key
PASSWORD_FOLDER = "passwords"
UPLOAD_FOLDER = "temp"

if not os.path.exists(PASSWORD_FOLDER):  # Ensure the password directory exists
    os.makedirs(PASSWORD_FOLDER)

if not os.path.exists(UPLOAD_FOLDER):  # Ensure the upload directory exists
    os.makedirs(UPLOAD_FOLDER)

manager = UserManager()

# Defines the file extensions allowed to be uploaded
allowed_extensions = {"json"}


def allowed_file(filename):
    """
    Verifies if the file is a json file
    """
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def validate_json_format(data):
    """
    Checks if the json file is in a suitable format for parsing
    """
    if not isinstance(data, dict):  # Check if the data is a dictionary
        return False

    for _, value in data.items():  # Iterate through the dictionary
        if (
            not isinstance(value, list) or len(value) != 2
        ):  # For each key, check if the corresponding value is a list and has exactly 2 elements
            return False

    return True


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """
    Renders the upload page and handles file uploads.
    """
    if "username" not in session:  # Checks if a user is logged in
        return redirect(url_for("login"))

    user = manager.find_user(session["username"])
    if user is None:
        return redirect(url_for("login"))

    if session.get("password_expired", False):
        flash("Your password has expired. Please change it.", "change_password")
        return redirect(url_for("profile"))

    merged_path = os.path.join(PASSWORD_FOLDER, f"{user.username}_passwords.json")
    user.password_manager.load_passwords(merged_path)  # Loads password data from a file

    if "load_password" in request.form:
        if (
            "file" not in request.files
        ):  # If form submission process is invalid for files
            flash("No file part", "invalid_file")
            return redirect(request.url)

        file = request.files["file"]  # Gets the file

        if file.filename == "":  # If there is no file, return
            flash("No file detected, please try again.", "invalid_file")
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            flash(f"File {filename} uploaded successfully!")
            temp_merged_path = os.path.join(
                UPLOAD_FOLDER, filename
            )  # Path to the uploaded file

            with open(temp_merged_path, "r", encoding="utf-8") as file:
                json_data = json.load(file)

            if validate_json_format(json_data):
                user.password_manager.append_passwords(temp_merged_path)
                user.password_manager.save_passwords(merged_path)
                os.remove(temp_merged_path)
                return redirect(url_for("dashboard"))

            else:
                os.remove(temp_merged_path)
                flash(
                    "Invalid json format, please try a different file.", "invalid_file"
                )
                return redirect(request.url)

        else:
            flash("Invalid file type, please try again.", "invalid_file")
            return redirect(request.url)

    # Add a final return for GET requests or when no form is submitted.
    return render_template("upload.html")


@app.route("/download/<filename>")
def download(filename):
    """
    Downloads a file from the password directory.
    """
    return send_from_directory(PASSWORD_FOLDER, filename, as_attachment=True)


@app.route("/")
def home():
    """
    Renders the home page. If a user is logged in, redirects to the dashboard.
    """
    if "username" in session:  # Checks if a user is logged in
        return redirect(url_for("dashboard"))
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Renders the register page and handles user registration.
    """
    if request.method == "POST":  # If POST request, process form data
        username = request.form["username"]
        if any(not char.isalnum() for char in username):
            flash("Username must be alphanumeric.", "invalid_register")
            return render_template("register.html")
        elif len(username) > 20:
            flash("Username is too long.", "invalid_register")
            return render_template("register.html")
        date = datetime.now()
        password = request.form["password"]
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
        if score != 4:
            flash("Password does not meet requirements.", "invalid_register")
            return render_template("register.html")
        if manager.add_user(username, password, date):
            manager.save_users("users.csv")
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Username already exists. Please try another.", "invalid_register")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Renders the login page and handles user login.
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = manager.find_user(username)
        if user and user.check_password(password):
            session["username"] = username

            if isinstance(user.change_password_time, str):
                if datetime.now() - datetime.fromisoformat(
                    user.change_password_time
                ) > timedelta(seconds=120):
                    flash(
                        "Your password has expired. Please change it.",
                        "change_password",
                    )
                    session["password_expired"] = True
                    return redirect(url_for("profile"))

            else:
                if datetime.now() - user.change_password_time > timedelta(seconds=120):
                    flash(
                        "Your password has expired. Please change it.",
                        "change_password",
                    )
                    session["password_expired"] = True
                    return redirect(url_for("profile"))

            session["password_expired"] = False
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "invalid_login")
    return render_template("login.html")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    """
    Renders the dashboard page and handles password management.
    """
    if "username" not in session:
        return redirect(url_for("login"))

    user = manager.find_user(session["username"])
    if user is None:
        return redirect(url_for("login"))

    if session.get("password_expired", False):
        flash("Your password has expired. Please change it.", "change_password")
        return redirect(url_for("profile"))

    merged_path = os.path.join(PASSWORD_FOLDER, f"{user.username}_passwords.json")
    if not os.path.exists(merged_path):
        with open(merged_path, "w", encoding="utf-8") as f:
            json.dump({}, f)

    user.password_manager.load_passwords(merged_path)
    passwords = user.password_manager.get_passwords()

    service_to_view = None
    password_to_view = None
    service_username_to_view = None
    service_username_to_remove = None
    password_strength_warning = None
    generated_password = session.get("generated_password", None)
    pwned_count = 0
    searched_password = session.get("searched_password", None)

    if "generate_password" in request.form:
        generated_password = user.password_manager.generate_password()
        session["generated_password"] = generated_password

    elif "add_password" in request.form:
        service_name = request.form["service_name"]
        service_password = request.form["service_password"]
        service_username = request.form["service_username"]
        user.password_manager.add_password(
            service_name, service_username, service_password
        )
        user.password_manager.save_passwords(merged_path)
        session.pop("generated_password", None)
        return redirect(url_for("dashboard"))

    elif "toggle_view_service" in request.form:
        incoming_service = request.form["toggle_view_service"]
        if session.get("toggled_service") == incoming_service:
            service_to_view = None
            session.pop("toggled_service", None)
        else:
            service_to_view = incoming_service
            session["toggled_service"] = incoming_service
            service_username_to_view = user.password_manager.get_service_username(
                service_to_view
            )
            password_to_view = user.password_manager.get_password(service_to_view)
            password_strength_warning = user.password_manager.check_password_strength(
                password_to_view
            )
            pwned_count = user.password_manager.check_pwned_password(password_to_view)

    elif "change_service_name" in request.form:
        new_service = request.form["change_service_name"]
        if (
            new_service not in user.password_manager.stored_passwords
        ):  # If new service is unique
            user.password_manager.change_service_name(
                session["toggled_service"], new_service
            )
            user.password_manager.save_passwords(merged_path)
            return redirect(url_for("dashboard"))
        else:
            flash(
                "Another service with the same name already exists. Please try again.",
                "change_error",
            )

    elif "change_service_username" in request.form:
        new_username = request.form["change_service_username"]
        user.password_manager.change_service_username(
            session["toggled_service"], new_username
        )  # Replaces the username for the respective service
        user.password_manager.save_passwords(merged_path)
        return redirect(url_for("dashboard"))

    elif "change_service_password" in request.form:
        new_password = request.form["change_service_password"]
        user.password_manager.change_service_password(
            session["toggled_service"], new_password
        )  # Replaces the password for the respective service
        user.password_manager.save_passwords(merged_path)
        return redirect(url_for("dashboard"))

    elif "remove_service" in request.form:
        service_to_remove = request.form["remove_service"]
        user.password_manager.remove_password(service_to_remove)
        user.password_manager.save_passwords(merged_path)
        return redirect(url_for("dashboard"))

    elif "search_password" in request.form:
        searched_password = request.form["search_password"]
        session["searched_password"] = searched_password

    return render_template(
        "dashboard.html",
        username=user.username,
        passwords=passwords,
        service_to_view=service_to_view,
        service_username_to_view=service_username_to_view,
        password_to_view=password_to_view,
        password_strength_warning=password_strength_warning,
        service_username_to_remove=service_username_to_remove,
        searched_password=searched_password,
        pwned_count=pwned_count,
        generated_password=generated_password,
    )


@app.route("/profile", methods=["GET", "POST"])
def profile():
    """
    Allows the user to change their username and password.
    """
    if "username" not in session:  # Checks if a user is logged in
        return redirect(url_for("login"))

    user = manager.find_user(session["username"])
    if user is None:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        if user and user.check_password(
            current_password
        ):  # Checks if the password is correct

            if user.password_manager.check_password_strength(new_password) != "Strong":
                flash("Password does not meet requirements.", "invalid_profile")
                return render_template("profile.html", username=user.username)

            if new_password != confirm_password:
                flash(
                    "New Password and Confirm New Password does not match.",
                    "invalid_profile",
                )
                return render_template("profile.html", username=user.username)

            if new_password == current_password:
                flash(
                    "New Password cannot be the same as your current password.",
                    "invalid_profile",
                )
                return render_template("profile.html", username=user.username)

            user.change_password(new_password)
            manager.save_users("users.csv")
            session["password_expired"] = False
            flash("Successfully changed password.", "success_profile")
        else:
            flash("Password is wrong.", "invalid_profile")

    return render_template("profile.html", username=user.username)


@app.route("/logout")  # manage the logout route
def logout():
    """
    Logs out the current user by removing the username from the session.
    """
    session.pop("username", None)
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
