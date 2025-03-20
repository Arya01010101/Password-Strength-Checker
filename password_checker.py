import tkinter as tk
from tkinter import messagebox
import re  # For regex (to check password patterns)
import hashlib  # For hashing the password

def check_password_strength(password):
    # Check if the password is at least 8 characters long
    if len(password) < 8:
        return "Weak: Password should be at least 8 characters long."
    
    # Check if the password contains at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return "Weak: Password should contain at least one uppercase letter."
    
    # Check if the password contains at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return "Weak: Password should contain at least one lowercase letter."
    
    # Check if the password contains at least one digit
    if not re.search(r'[0-9]', password):
        return "Weak: Password should contain at least one digit."
    
    # Check if the password contains at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Weak: Password should contain at least one special character."
    
    # If all checks pass, the password is strong
    return "Strong: Password meets all requirements."

def hash_password(password):
    # Hash the password using SHA-256
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    # Create the main window
    window = tk.Tk()
    window.title("Password Strength Checker")
    window.geometry("400x300")  # Set the window size

    # Function to check password strength
    def check_password():
        password = entry.get()  # Get the password from the input field
        strength = check_password_strength(password)  # Check strength
        hashed_password = hash_password(password)  # Hash the password

        # Show the results in a message box
        messagebox.showinfo("Results", f"{strength}\nHashed Password: {hashed_password}")

    def clear_input():
     entry.delete(0, tk.END)  # Clear the input field

    # Create a label for instructions
    label = tk.Label(window, text="Enter your password:", font=("Arial", 14))
    label.pack(pady=10)

    # Create an input field for the password
    entry = tk.Entry(window, show="*", font=("Arial", 12))
    entry.pack(pady=10)

    # Create a button to check the password
    button = tk.Button(window, text="Check Password", command=check_password, font=("Arial", 12))
    button.pack(pady=10)

    # Add this button after the "Check Password" button
    clear_button = tk.Button(window, text="Clear", command=clear_input, font=("Arial", 12))
    clear_button.pack(pady=10)



    # Run the main loop
    window.mainloop()

if __name__ == "__main__":
    main()
    
    # Ask the user to input a password
    password = input("Enter your password: ")
    
    # Check the strength of the password
    strength = check_password_strength(password)
    print(strength)
    
    # Hash the password and display the hashed value
    hashed_password = hash_password(password)
    print(f"Hashed Password: {hashed_password}")

    

