import tkinter as tk
from tkinter import messagebox, ttk
import random
import cryptography.fernet
import pyperclip
import json
import os 
import hashlib
import cryptography

# File paths
file_path = "passwords.json"
credentials_file_path = "credentials.json"
icon_file = "icon.ico"
logo_file = "logo.png"
encryption_key_file = "key.key"

# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def Password_generator():
    password_entry.delete(0, 'end')

    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
               'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
               'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    nr_letters = random.randint(8, 10)
    nr_symbols = random.randint(2, 4)
    nr_numbers = random.randint(2, 4)

    password_list = []

    for char in range(nr_letters):
        password_list.append(random.choice(letters))

    for char in range(nr_symbols):
        password_list += random.choice(symbols)

    for char in range(nr_numbers):
        password_list += random.choice(numbers)

    random.shuffle(password_list)

    password = ""
    for char in password_list:
        password += char

    password_entry.insert(0, password)

    pyperclip.copy(password)


# ---------------------------- SAVE PASSWORD ------------------------------- #
def save_entries():
    website_text = website_entry.get()
    user_text = user_entry.get()
    password_text = password_entry.get()

    new_data = {
        website_text: {
            "user": user_text,
            "password": password_text,
        }
    }

    if not website_text or not password_text:
        messagebox.showinfo("Warning", "One or more boxes is left blank ... please fill all boxes.")
        return

    try:
        with open(file_path, "r") as file:
            data = json.load(file)
            # Decrypt the data
            data = json.loads(decrypt_data(data['data'], key))
    except FileNotFoundError:
        data = {}

    data.update(new_data)

    encrypted_data = encrypt_data(json.dumps(data), key)

    with open(file_path, "w") as file:
        json.dump({'data': encrypted_data}, file)

    website_entry.delete(0, 'end')
    password_entry.delete(0, 'end')


# ---------------------------- SEARCH PASSWORDS ------------------------------- #
def search_entries():
    website = website_entry.get()
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            data = json.loads(decrypt_data(data['data'], key))
    except FileNotFoundError:
        messagebox.showinfo("Error", "No data file found")
        return

    if website in data:
        user = data[website]["user"]
        password = data[website]["password"]
        messagebox.showinfo(title=website, message=f"User: {user}\nPassword: {password}")
    else:
        messagebox.showinfo("Info", "No such website stored in our data")

# ---------------------------- SHOW ALL PASSWORDS ------------------------------- #
def show_all_passwords():
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            data = json.loads(decrypt_data(data['data'], key))
    except (FileNotFoundError, json.JSONDecodeError):
        messagebox.showinfo("Error", "No data file found")
        return

    if data:
        all_passwords_window = tk.Toplevel(main_window)
        all_passwords_window.title("All Stored Passwords")
        all_passwords_window.geometry("600x400")

        tree = ttk.Treeview(all_passwords_window, columns=("Website", "User", "Password"), show='headings')
        tree.heading("Website", text="Website")
        tree.heading("User", text="User")
        tree.heading("Password", text="Password")

        for website, info in data.items():
            tree.insert("", "end", values=(website, info["user"], info["password"]))

        tree.pack(fill='both', expand=True)

        def on_key_release(event):
            selected_item = tree.selection()
            if selected_item:
                values = tree.item(selected_item[0], "values")
                status_label.config(text=f"Website: {values[0]}, User: {values[1]}, Password: {values[2]}")
            else:
                status_label.config(text="")

        def delete_selected_item():
            selected_item = tree.selection()
            if selected_item:
                values = tree.item(selected_item[0], "values")
                website_to_delete = values[0]
                del data[website_to_delete]
                encrypted_data = encrypt_data(json.dumps(data), key)
                with open(file_path, "w") as file:
                    json.dump({'data': encrypted_data}, file)
                tree.delete(selected_item)
                status_label.config(text="")

        def edit_selected_item():
            selected_item = tree.selection()
            if selected_item:
                values = tree.item(selected_item[0], "values")
                website_to_edit = values[0]

                edit_window = tk.Toplevel(all_passwords_window)
                edit_window.title(f"Edit {website_to_edit}")
                edit_window.geometry("400x200")

                tk.Label(edit_window, text="User:").pack(pady=5)
                user_entry_edit = tk.Entry(edit_window)
                user_entry_edit.pack(pady=5)
                user_entry_edit.insert(0, values[1])

                tk.Label(edit_window, text="Password:").pack(pady=5)
                password_entry_edit = tk.Entry(edit_window, show='*')
                password_entry_edit.pack(pady=5)
                password_entry_edit.insert(0, values[2])

                def save_edits():
                    new_user = user_entry_edit.get()
                    new_password = password_entry_edit.get()
                    if not new_user or not new_password:
                        messagebox.showinfo("Warning", "One or more boxes is left blank ... please fill all boxes.")
                        return

                    data[website_to_edit] = {
                        "user": new_user,
                        "password": new_password
                    }
                    encrypted_data = encrypt_data(json.dumps(data), key)
                    with open(file_path, "w") as file:
                        json.dump({'data': encrypted_data}, file)

                    tree.item(selected_item[0], values=(website_to_edit, new_user, new_password))
                    edit_window.destroy()

                tk.Button(edit_window, text="Save", command=save_edits).pack(pady=15)

        tree.bind("<KeyRelease>", on_key_release)

        scrollbar = ttk.Scrollbar(all_passwords_window, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        status_label = tk.Label(all_passwords_window, text="", anchor="w")
        status_label.pack(fill="x")

        tk.Button(all_passwords_window, text="Delete Selected", command=delete_selected_item).pack(pady=10)
        tk.Button(all_passwords_window, text="Edit Selected", command=edit_selected_item).pack(pady=10)

        tree.focus_set()
    else:
        messagebox.showinfo("Info", "No passwords stored yet")

# ---------------------------- Hahing Utility ------------------------------- #
def hash_password(password):
    return hashlib.sha3_512(password.encode()).hexdigest()


# ---------------------------- SAVE CREDENTIALS ------------------------------- #
def save_credentials(username, password):
    credentials = {username: hash_password(password)}
    with open(credentials_file_path, 'w') as file:
        json.dump(credentials, file)


# ---------------------------- VERIFY CREDENTIALS ------------------------------- #
def verify_credentials(username, password):
    if os.path.exists(credentials_file_path):
        with open(credentials_file_path, 'r') as file:
            credentials = json.load(file)
            return credentials.get(username) == hash_password(password)
    return False


# ---------------------------- LOGIN WINDOW ------------------------------- #
def login():
    login_window = tk.Tk()
    login_window.title("Login to Passwords Manager")
    login_window.geometry("400x200")
    login_window.iconbitmap(icon_file)

    user_label = tk.Label(login_window, text="User:")
    password_label = tk.Label(login_window, text="Password:")

    user_entry = tk.Entry(login_window)
    user_entry.focus()
    password_entry = tk.Entry(login_window, show='*')

    user_label.pack(pady=5)
    user_entry.pack(pady=5)
    password_label.pack(pady=5)
    password_entry.pack(pady=5)

    def attempt_login(event=None):
        global key
        key = load_key()
        username = user_entry.get()
        password = password_entry.get()
        if verify_credentials(username, password):
            # messagebox.showinfo("Success", "You are logged in successfully")
            login_window.destroy()
            main_app()
        else:
            messagebox.showerror("Error", "Invalid credentials")

    user_entry.bind("<Return>", attempt_login)
    password_entry.bind("<Return>", attempt_login)
    tk.Button(login_window, text="Login", command=attempt_login).pack(pady=15)
    login_window.mainloop()


# ---------------------------- SIGNUP WINDOW ------------------------------- #
def signup():
    signup_window = tk.Tk()
    signup_window.title("Sign up to Passwords Manager")
    signup_window.geometry("400x200")
    signup_window.iconbitmap(icon_file)

    user_label = tk.Label(signup_window, text="Create user:")
    password_label = tk.Label(signup_window, text="Create password:")
    pass_verify_label = tk.Label(signup_window, text="Verify password:")

    user_entry = tk.Entry(signup_window)
    user_entry.focus()
    password_entry = tk.Entry(signup_window, show='*')
    pass_verify_entry = tk.Entry(signup_window, show='*')

    user_label.pack(pady=5)
    user_entry.pack(pady=5)
    password_label.pack(pady=5)
    password_entry.pack(pady=5)
    pass_verify_entry.pack(pady=5)

    def create_account(event=None):
        username = user_entry.get()
        password = password_entry.get()
        password_verify = pass_verify_entry.get()
        if len(password) == 0 or len(username) == 0 or len(password_verify) == 0:
            messagebox.showerror("Error", "Cant create a user you left the username or password empty.")
        elif password != password_verify:
            messagebox.showerror("Error", "The passwords do not match, please try again")
        else:
            save_credentials(username, password)
            generate_key()
            messagebox.showinfo("Success", "Account created successfully")
            signup_window.destroy()
            login()

    user_entry.bind("<Return>", create_account)
    password_entry.bind("<Return>", create_account)
    pass_verify_entry.bind("<Return>", create_account)        
    tk.Button(signup_window, text="Sign Up", command=create_account).pack(pady=15)

    signup_window.mainloop()


# ---------------------------- ENCRYPTION / DECRYPTION ------------------------------- #
def generate_key():
    key = cryptography.fernet.Fernet.generate_key()
    with open(encryption_key_file, 'wb') as key_file:
        key_file.write(key)


def load_key():
    return open(encryption_key_file, 'rb').read()


def encrypt_data(data, key):
    fernet = cryptography.fernet.Fernet(key)
    return fernet.encrypt(data.encode()).decode()


def decrypt_data(data, key):
    fernet = cryptography.fernet.Fernet(key)
    return fernet.decrypt(data.encode()).decode()

        
# ---------------------------- UI SETUP ------------------------------- #
def main_app():
    global main_window
    main_window = tk.Tk()
    main_window.title("Password Manager created by Amos Mesika")
    main_window.config(padx=40, pady=40)

    main_window.iconbitmap(icon_file)

    website = tk.StringVar()
    canvas = tk.Canvas(width=200, height=200)
    photo = tk.PhotoImage(file=logo_file)
    canvas.create_image(100, 100, image=photo)
    canvas.grid(column=1, row=0)

    website_label = tk.Label(text="Website:")
    website_label.grid(column=0, row=1)
    
    global website_entry
    website_entry = tk.Entry(width=36)
    website_entry.focus()
    website_entry.grid(row=1, column=1)

    user_label = tk.Label(text="Email/Username:")
    user_label.grid(column=0, row=2)

    global user_entry
    user_entry = tk.Entry(width=55)
    user_entry.insert("0", "example@test.com")
    user_entry.grid(row=2, column=1, columnspan=2)

    password_label = tk.Label(text="Password:")
    password_label.grid(column=0, row=3)

    global password_entry
    password_entry = tk.Entry(width=36, show='*')
    password_entry.grid(row=3, column=1)

    pass_gen_button = tk.Button(text="Generate Password", command=Password_generator)
    pass_gen_button.grid(row=3, column=2)

    add_button = tk.Button(text="Add", width=47, command=save_entries)
    add_button.grid(row=4, column=1, columnspan=2)

    search_button = tk.Button(text="Search", width=15, command=search_entries)
    search_button.grid(row=1, column=2)

    show_all_button = tk.Button(text="Show all passwords", width=47, command=show_all_passwords)
    show_all_button.grid(row=5, column=1, columnspan=2)

    main_window.mainloop()

# ---------------------------- ENTRY POINT ------------------------------- #

if not os.path.exists(credentials_file_path) or os.stat(credentials_file_path).st_size == 0:
    signup()
else:
    login()
