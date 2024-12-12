import sys
import hashlib
import json
import customtkinter as ctk
from tkinter import messagebox, filedialog
from sympy import randprime
import datetime
import csv
import os
import requests 
import base64

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

    def authenticate(self, username, nonce=None ,  nonce_size=32):
        """Simulate KDC's challenge-response authentication using a nonce."""
        if nonce is None : 
            nonce = [random.randint(0,255) for _ in range(nonce_size)] 
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
    nonce , signed_nonce, auth_status = kdc.authenticate("Alice")
    print("\nStep 1: KDC generates a nonce for Alice:", nonce)

    print(f"KDC authenticates Alice: {auth_status}")
    print("Alice signs the nonce with her private key:", signed_nonce)

    print("\nStep 2: Bob requests Alice's public key from the KDC.")
    alice_public_key_for_bob = kdc.get_public_key("Alice")
    print("KDC provides Alice's public key to Bob:", alice_public_key_for_bob)


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
    try:
       response = requests.post(url, headers=headers, json=payload)
       response.raise_for_status() 
       return response.json()
    except requests.exceptions.RequestException as e:
        print(f" Error querying model: {e}") 
        return None 

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
            if response:
             answer = response["choices"][0]["message"]["content"]
             print(f"Chatbot: {answer}\n")
        except (KeyError , IndexError) as e:
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
    while b :
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    try: 
        return pow(e,-1, phi) 
    except ValueError: 
        raise ValueError("Multiplicative inverse does not exist")

def generate_unique_primes(bits): 
    def generate_prime(): 
        return randprime( 2 ** (bits // 2-1 ), 2**(bits // 2))
    p = generate_prime()
    q = generate_prime()
    while p == q:
        q = generate_prime() 
    return p , q
    

def encrypt(pk, plaintext):
    key, n = pk 
    encrypted_bytes = bytes(pow(byte, key ,n ) for byte in plaintext.encode())
    return  base64.b64encode(encrypted_bytes).decode()

def decrypt(pk, ciphertext):
    key, n = pk 
    encrypted_bhytes = base64.b64decode(ciphertext.encode()) 
    decrypted_bytes= bytes(pow(byte, key, n ) for byte in encrypted_bytes  )
    return decrypted_bytes.decode()