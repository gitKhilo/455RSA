import sys

import hashlib
import json
import customtkinter as ctk
from tkinter import messagebox, filedialog
import datetime
import csv
import os
import requests
import random
from sympy import randprime
GROQ_API_KEY = "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"
GROQ_API_BASE_URL = "https://api.groq.com/openai/v1"

### !! START OF KDC TUTORIAL !! ###

# Simulated Key Distribution Center (KDC)
class KDC:
    def __init__(self):
        self.user_keys = {}  # Dictionary to store user keys

    def register_user(self, username, key_size=1024):
        """Register a new user and generate their RSA key pair."""
        if username in self.user_keys:
            return f"User '{username}' is already registered."
        public_key, private_key = generate_key_pair(key_size)
        self.user_keys[username] = {"public_key": public_key, "private_key": private_key}
        return f"User '{username}' registered successfully!"

    def get_public_key(self, username):
        """Get the public key of a registered user."""
        if username not in self.user_keys:
            return f"User '{username}' not found."
        return self.user_keys[username]["public_key"]

    def authenticate(self, username, nonce):
        """Simulate KDC's challenge-response authentication using a nonce."""
        if username not in self.user_keys:
            return None, "User not found!"

        private_key = self.user_keys[username]["private_key"]
        # Encrypt the nonce with the user's private key (sign it)
        signed_nonce = [pow(n, private_key[0], private_key[1]) for n in nonce]
        return signed_nonce, "Authenticated"
    
kdc = KDC()

def run_kdc_tutorial():
    
    print(kdc.register_user("Alice", key_size=1024))
    print(kdc.register_user("Bob", key_size=2048))

    alice_public_key = kdc.get_public_key("Alice")
    bob_public_key = kdc.get_public_key("Bob")
    print("\nPublic Key of Alice:", alice_public_key)
    print("Public Key of Bob:", bob_public_key)

    print("\n--- Step-by-Step Communication ---")
    nonce = [random.randint(0, 255) for _ in range(8)]
    print("\nStep 1: KDC generates a nonce for Alice:", nonce)
    signed_nonce, auth_status = kdc.authenticate("Alice", nonce)
    print(f"KDC authenticates Alice: {auth_status}")
    print("Alice signs the nonce with her private key:", signed_nonce)

    print("\nStep 2: Bob requests Alice's public key from the KDC.")
    bob_requests_alice_key = kdc.get_public_key("Alice")
    print("KDC provides Alice's public key to Bob:", bob_requests_alice_key)


    message = input("\nStep 3: Alice writes a message to send to Bob: ")
    ciphertext = encrypt(bob_public_key, message)
    print("Alice encrypts the message using Bob's public key:", ciphertext)


    print("\nStep 4: Bob receives the encrypted message and decrypts it.")
    bob_private_key = kdc.user_keys["Bob"]["private_key"]
    decrypted_message = decrypt(bob_private_key, ciphertext)
    print("Bob decrypts the message using his private key:", decrypted_message)


    verified_nonce = [pow(n, alice_public_key[0], alice_public_key[1]) for n in signed_nonce]
    print("\nStep 5: Bob verifies Alice's identity by validating the signed nonce.")
    print("Verified Nonce:", verified_nonce)
    print("Nonce Match:", nonce == verified_nonce)

### COMMENTED OUT BECAUSE KDC TUTORIAL RUNS IF USER PRESSES RUN KDC TUTORIAL BUTTON ###
# run_kdc_tutorial()

### !! END OF KDC TUTORIAL !! ###
            ###
### !! START OF RSA CHATBOT !! ###

# Function to retrieve available models for GROQ
def list_available_models():
    url = f"{GROQ_API_BASE_URL}/models"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        print("Available Models:")
        for model in response.json().get("data", []):
            print(f"- {model['id']}")
    else:
        print(f"Error fetching models: {response.status_code} - {response.text}")

# Function to query the Groq LLM API
def query_groq_llm(prompt):
    url = f"{GROQ_API_BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama3-8b-8192",  # Replace with a valid model ID
        "messages": [
            {"role": "system", "content": "You are an assistant specialized in RSA encryption and cryptography. Provide detailed and accurate answers."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 500
    }
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Error querying model: {response.status_code} - {response.text}")

# Main chatbot loop 

def rsa_chatbot():
    print("Welcome to the RSA Chatbot!")
    print("Ask me anything about RSA encryption, cryptography, or related topics.")
    print("Type 'exit' and press Enter to leave the chat.\n")

    while True:
        user_input = input("You: ").strip()
        if user_input.lower() == "exit":
            print("Goodbye! Feel free to return anytime.")
            break

        try:
            print("Processing your question...\n")
            response = query_groq_llm(user_input)
            answer = response["choices"][0]["message"]["content"]
            print(f"Chatbot: {answer}\n")
        except Exception as e:
            print(f"An error occurred: {e}\n")
            
### COMMENTED OUT BECAUSE INITIALIZING CHATBOT DONE IN FRONTEND ###
# if __name__ == "__main__":
#     print("Verifying available models...")
#     list_available_models()
#     print("\nStarting the RSA Chatbot...\n")
#     rsa_chatbot()

### !! END OF RSA CHATBOT !! ###
        ###
#REST OF CODE:

# Utility functions for RSA
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d = 0
    x1, x2, y1 = 0, 1, 1
    temp_phi = phi
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi, e = e, temp2
        x, y = x2 - temp1 * x1, d - temp1 * y1
        x2, x1, d, y1 = x1, x, y1, y
    if temp_phi == 1:
        return d + phi

def generate_key_pair(bits):
    p = randprime(2 ** (bits // 2 - 1), 2 ** (bits // 2))
    q = randprime(2 ** (bits // 2 - 1), 2 ** (bits // 2))
    while p == q:
        q = randprime(2 ** (bits // 2 - 1), 2 ** (bits // 2))
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    key, n = pk
    return [pow(ord(char), key, n) for char in plaintext]

def decrypt(pk, ciphertext):
    key, n = pk
    return ''.join([chr(pow(char, key, n)) for char in ciphertext])

# CustomTkinter Application
class RSAApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")  # Set dark mode
        ctk.set_default_color_theme("dark-blue")  # Optional: set a color theme
        self.title("Enhanced RSA Application")
        self.geometry("800x600")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.users_file_path = os.path.join(
            os.path.expanduser("~"), 
            "OneDrive - American University of Beirut", 
            "Desktop", 
            "database", 
            "users.json"
        )
        self.users = self.load_users()
        self.current_user = None
        self.public_key = None
        self.private_key = None
        self.ciphertext = None
        self.history_page = ctk.CTkFrame(self)  # Add history page
        self.init_ui()

    def load_users(self):
        try:
            with open(self.users_file_path, "r") as file:
                users = json.load(file)
                # Ensure each user's history is a list of dictionaries
                for user in users:
                    if not isinstance(users[user].get("history", []), list):
                        users[user]["history"] = []
                    else:
                        # Ensure each entry in history is a dictionary
                        users[user]["history"] = [
                            entry if isinstance(entry, dict) else {} for entry in users[user]["history"]
                        ]
                return users
        except FileNotFoundError:
            return {}

    def save_users(self):
        # Create the directory if it doesn't exist
        directory = os.path.dirname(self.users_file_path)
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        with open(self.users_file_path, "w") as file:
            json.dump(self.users, file)

    def init_ui(self):
        # Create frames for each page
        self.login_page = ctk.CTkFrame(self)
        self.tutorial_page = ctk.CTkFrame(self)
        self.enc_dec_page = ctk.CTkFrame(self)
        self.history_page = ctk.CTkFrame(self)  # Add history page

        # Setup each page
        self.setup_login_page()
        self.setup_tutorial_page()
        self.setup_enc_dec_page()
        self.setup_history_page()  # Setup history page

        # Show login page initially
        self.show_frame(self.login_page)

    def show_frame(self, frame):
        frame.tkraise()

    def setup_login_page(self):
        self.login_page.grid(row=0, column=0, sticky='nsew')
        layout = ctk.CTkFrame(self.login_page)
        layout.place(relx=0.5, rely=0.5, anchor='center')

        ctk.CTkLabel(layout, text="Username:").pack(pady=10)
        self.username_input = ctk.CTkEntry(layout)
        self.username_input.pack(pady=5)

        ctk.CTkLabel(layout, text="Password:").pack(pady=10)
        self.password_input = ctk.CTkEntry(layout, show='*')
        self.password_input.pack(pady=5)

        ctk.CTkButton(layout, text="Login", command=self.login_user).pack(pady=10)
        ctk.CTkButton(layout, text="Register", command=self.register_user).pack(pady=5)

    def setup_tutorial_page(self):
        self.tutorial_page.grid(row=0, column=0, sticky='nsew')
        layout = ctk.CTkFrame(self.tutorial_page)
        layout.place(relx=0.5, rely=0.5, anchor='center')

        tutorial_text = (
            "Welcome to the RSA Tutorial!\n\n"
            "RSA is a public key cryptosystem that enables secure communication. It involves generating two keys:\n"
            "- A public key, which is shared openly and used to encrypt messages.\n"
            "- A private key, which is kept secret and used to decrypt messages.\n\n"
            "In this example, we'll generate a pair of keys, encrypt a simple message ('Hello'), "
            "and then decrypt it using the private key.\n\n"
            "Click 'Next' to generate the keys and continue with the example."
        )
        self.tutorial_label = ctk.CTkLabel(layout, text=tutorial_text, wraplength=600)
        self.tutorial_label.pack(pady=10)

        self.next_button = ctk.CTkButton(layout, text="Next", command=self.show_tutorial_example)
        self.next_button.pack(pady=10)

    def show_tutorial_example(self):
        # Example: Generate a key pair, encrypt a message, and decrypt it
        self.public_key, self.private_key = generate_key_pair(256)
        example_message = "Hello"
        encrypted_message = encrypt(self.public_key, example_message)
        decrypted_message = decrypt(self.private_key, encrypted_message)

        example_text = (
            "Example:\n\n"
            f"Generated Public Key: {self.public_key}\n"
            f"Generated Private Key: {self.private_key}\n\n"
            f"Original Message: {example_message}\n"
            f"Encrypted Message: {encrypted_message}\n"
            f"Decrypted Message: {decrypted_message}\n\n"
            "Now that you've seen how RSA works, click 'Proceed' to start using the application."
        )
        self.tutorial_label.configure(text=example_text)
        self.next_button.configure(text="Proceed", command=lambda: self.show_frame(self.enc_dec_page))

    def setup_enc_dec_page(self):
        self.enc_dec_page.grid(row=0, column=0, sticky='nsew')

        # Create a scrollable frame
        scrollable_frame = ctk.CTkScrollableFrame(self.enc_dec_page, width=750, height=550)
        scrollable_frame.pack(padx=20, pady=20, fill="both", expand=True)

        # Key Size Selection
        ctk.CTkLabel(scrollable_frame, text="Key Size (bits):").pack(pady=10)
        self.key_size_var = ctk.IntVar(value=1024)
        ctk.CTkRadioButton(scrollable_frame, text="1024", variable=self.key_size_var, value=1024).pack(pady=5)
        ctk.CTkRadioButton(scrollable_frame, text="2048", variable=self.key_size_var, value=2048).pack(pady=5)

        # Generate Keys
        ctk.CTkButton(scrollable_frame, text="Generate Keys", command=self.generate_keys).pack(pady=10)
        self.keys_display = ctk.CTkTextbox(scrollable_frame, height=5, state='disabled')
        self.keys_display.pack(pady=5)
        ctk.CTkButton(scrollable_frame, text="Show Full Keys", command=self.show_full_keys).pack(pady=5)

        # Encryption Section
        ctk.CTkLabel(scrollable_frame, text="Plaintext Message:").pack(pady=10)
        self.message_input = ctk.CTkEntry(scrollable_frame)
        self.message_input.pack(pady=5)

        ctk.CTkButton(scrollable_frame, text="Encrypt", command=self.encrypt_message).pack(pady=10)
        self.ciphertext_display = ctk.CTkTextbox(scrollable_frame, height=5, state='disabled')
        self.ciphertext_display.pack(pady=5)
        ctk.CTkButton(scrollable_frame, text="Show Full Ciphertext", command=self.show_full_ciphertext).pack(pady=5)

        # Encryption Explanation
        ctk.CTkLabel(
            scrollable_frame,
            text=(
                "Encryption Process:\n"
                "1. A public key (PU = {e, n}) is used for encryption.\n"
                "2. Each character in the plaintext is converted to its Unicode value.\n"
                "3. Each value is encrypted as:\n"
                "   Encrypted Value = (Unicode Value ^ e) mod n\n"
                "4. The result is a series of encrypted values, forming the ciphertext."
            ),
            wraplength=700,
            justify='left',
        ).pack(pady=10)

        # Decryption Section
        ctk.CTkLabel(scrollable_frame, text="Enter Ciphertext to Decrypt:").pack(pady=10)
        self.decryption_input = ctk.CTkTextbox(scrollable_frame, height=5)
        self.decryption_input.pack(pady=5)

        ctk.CTkButton(scrollable_frame, text="Decrypt", command=self.decrypt_message).pack(pady=10)
        self.decrypted_message_display = ctk.CTkEntry(scrollable_frame, state='readonly')
        self.decrypted_message_display.pack(pady=5)

        # Decryption Explanation
        ctk.CTkLabel(
            scrollable_frame,
            text=(
                "Decryption Process:\n"
                "1. A private key (PR = {d, n}) is used for decryption.\n"
                "2. Each encrypted value is processed as:\n"
                "   Original Value = (Encrypted Value ^ d) mod n\n"
                "3. Each decrypted value is converted back to its character using Unicode.\n"
                "4. The characters are combined to reconstruct the plaintext."
            ),
            wraplength=700,
            justify='left',
        ).pack(pady=10)

        # RSA Key Setup Explanation
        ctk.CTkLabel(
            scrollable_frame,
            text=(
                "RSA Key Setup:\n"
                "1. Choose two large prime numbers, p and q.\n"
                "2. Compute n = p × q (used as part of both keys).\n"
                "3. Calculate ϕ(n) = (p-1) × (q-1) (used for key generation).\n"
                "4. Select a public exponent e, where gcd(e, ϕ(n)) = 1.\n"
                "5. Calculate the private exponent d, satisfying:\n"
                "   (e × d) mod ϕ(n) = 1.\n"
                "6. Publish the public key (PU = {e, n}).\n"
                "7. Keep the private key (PR = {d, n}) secret."
            ),
            wraplength=700,
            justify='left',
        ).pack(pady=10)

        # Add a button to view user history
        ctk.CTkButton(scrollable_frame, text="View History", command=self.show_user_history).pack(pady=10)

    def setup_history_page(self):
        self.history_page.grid(row=0, column=0, sticky='nsew')
        layout = ctk.CTkFrame(self.history_page)
        layout.place(relx=0.5, rely=0.5, anchor='center')

        ctk.CTkLabel(layout, text="User History").pack(pady=10)
        self.history_display = ctk.CTkTextbox(layout, height=40, width=120, state='disabled')
        self.history_display.pack(pady=5)

        ctk.CTkButton(layout, text="Download History", command=self.download_history).pack(pady=5)
        ctk.CTkButton(layout, text="Clear History", command=self.clear_history).pack(pady=5)
        ctk.CTkButton(layout, text="Back", command=lambda: self.show_frame(self.enc_dec_page)).pack(pady=10)

    def login_user(self):
        username = self.username_input.get()
        password = self.password_input.get()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if username in self.users and self.users[username]["password"] == hashed_password:
            self.current_user = username
            messagebox.showinfo("Login Successful", f"Welcome, {username}!")
            self.show_frame(self.tutorial_page)
            self.update_user_history(f"User {username} logged in.")
        else:
            messagebox.showwarning("Login Failed", "Invalid username or password.")

    def register_user(self):
        username = self.username_input.get()
        password = self.password_input.get()
        if username in self.users:
            messagebox.showwarning("Registration Failed", "User already exists.")
        elif len(password) < 6:
            messagebox.showwarning("Registration Failed", "Password must be at least 6 characters.")
        else:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            self.users[username] = {"password": hashed_password, "history": []}
            self.save_users()
            messagebox.showinfo("Registration Successful", "User registered successfully.")
            self.update_user_history(f"User {username} registered.")

    def generate_keys(self):
        key_size = self.key_size_var.get()
        self.public_key, self.private_key = generate_key_pair(key_size)
        self.keys_display.configure(state='normal')
        self.keys_display.delete("1.0", ctk.END)
        self.keys_display.insert(ctk.END, f"Public Key: {self.public_key}\nPrivate Key: {self.private_key}")
        self.keys_display.configure(state='disabled')

    def encrypt_message(self):
        if not self.public_key:
            messagebox.showwarning("Error", "Generate keys first!")
            return
        plaintext = self.message_input.get()
        if not plaintext:
            messagebox.showwarning("Error", "Enter a message to encrypt.")
            return
        self.ciphertext = encrypt(self.public_key, plaintext)
        self.ciphertext_display.configure(state='normal')
        self.ciphertext_display.delete("1.0", ctk.END)
        self.ciphertext_display.insert(ctk.END, str(self.ciphertext))
        self.ciphertext_display.configure(state='disabled')
        self.update_user_history("Encryption", plaintext, str(self.ciphertext), str(self.public_key))

    def decrypt_message(self):
        if not self.private_key:
            messagebox.showwarning("Error", "Generate keys first!")
            return
        ciphertext = self.decryption_input.get("1.0", ctk.END).strip()
        try:
            ciphertext = eval(ciphertext)
            plaintext = decrypt(self.private_key, ciphertext)
            self.decrypted_message_display.configure(state='normal')
            self.decrypted_message_display.delete(0, ctk.END)
            self.decrypted_message_display.insert(0, plaintext)
            self.decrypted_message_display.configure(state='readonly')
            self.update_user_history("Decryption", plaintext, str(ciphertext), str(self.private_key))
        except Exception as e:
            messagebox.showerror("Error", f"Invalid ciphertext: {e}")

    def show_full_keys(self):
        if not self.public_key or not self.private_key:
            messagebox.showwarning("Error", "Generate keys first!")
            return
        messagebox.showinfo("Full Keys", f"Public Key: {self.public_key}\nPrivate Key: {self.private_key}")

    def show_full_ciphertext(self):
        if not self.ciphertext:
            messagebox.showwarning("Error", "No ciphertext available. Encrypt a message first!")
            return
        messagebox.showinfo("Full Ciphertext", f"Ciphertext: {self.ciphertext}")

    def update_user_history(self, action, plaintext=None, ciphertext=None, keys=None):
        if self.current_user:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            entry = {
                "action": action,
                "plaintext": plaintext,
                "ciphertext": ciphertext,
                "keys": keys,
                "timestamp": timestamp
            }
            # Ensure history is a list of dictionaries
            if not isinstance(self.users[self.current_user]["history"], list):
                self.users[self.current_user]["history"] = []
            self.users[self.current_user]["history"].append(entry)
            self.save_users()

    def show_user_history(self):
        if self.current_user:
            history = self.users[self.current_user].get("history", [])
            self.history_display.configure(state='normal')
            self.history_display.delete("1.0", ctk.END)
            for entry in history:
                timestamp = entry.get('timestamp', 'N/A')
                action = entry.get('action', 'N/A')
                plaintext = entry.get('plaintext', 'N/A')
                ciphertext = entry.get('ciphertext', 'N/A')
                keys = entry.get('keys', 'N/A')
                
                self.history_display.insert(ctk.END, f"{timestamp} - {action}\n"  )        
                self.history_display.insert(ctk.END, f"Plaintext: {plaintext}\n")
                self.history_display.insert(ctk.END, f"Ciphertext: {ciphertext}\n")
                self.history_display.insert(ctk.END, f"Keys: {keys}\n\n")
            self.history_display.configure(state='disabled')
            self.show_frame(self.history_page)

    def download_history(self):
        if self.current_user:
            history = self.users[self.current_user].get("history", [])
            file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
            if file_path:
                with open(file_path, 'w', newline='') as csvfile:
                    fieldnames = ['timestamp', 'action', 'plaintext', 'ciphertext', 'keys']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for entry in history:
                        writer.writerow(entry)
                messagebox.showinfo("Download Complete", f"History downloaded as {file_path}")

    def clear_history(self):
        if self.current_user:
            self.users[self.current_user]["history"] = []
            self.save_users()
            self.show_user_history()
            messagebox.showinfo("History Cleared", "User history has been cleared.")

if __name__ == "__main__":
    app = RSAApp()
    app.mainloop()
