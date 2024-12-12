 RSA Chatbot & Key Distribution Center (KDC)

This repository contains Python implementations for:
1. RSA-based Chatbot: A chatbot specializing in cryptography, interacting via the GROQ API.
2. Key Distribution Center (KDC): Simulates a secure exchange of public and private keys for encrypted communication.
3. CustomTkinter GUI: A user interface for RSA encryption/decryption tutorials and history tracking.

---

 Features
- Backend with `Tkinter`: Provides a GUI-based RSA encryption/decryption demo.
- Backend API: Includes a command-line-based RSA chatbot for cryptography-related queries.
- Key Management: Generates and manages RSA public/private keys for multiple users.
- Authentication: Simulates nonce-based challenge-response authentication.
- History Management: Stores user actions (login, key generation, encryption/decryption).

---

 File Structure
- `backend.py`: Command-line-based RSA Chatbot and KDC logic.
- `backend_with_tkinter.py`: GUI implementation using CustomTkinter for encryption tutorials.
- `env.py`: Loads environment variables for API keys using `python-dotenv`.
- `.env`: Contains sensitive API keys (e.g., `GROQ_API_KEY`).

---

 Setup Instructions
1. Install Dependencies:
   - Python 3.9+
   - Install required libraries: `pip install -r requirements.txt`.
   
2. Set up Environment:
   - Ensure `.env` is present with the `GROQ_API_KEY`.
   - Modify `backend_with_tkinter.py` for paths like `users.json`.

3. Run Applications:
   - RSA Chatbot:
    
     python backend.py
    
   - GUI Application:
    
     python backend_with_tkinter.py
    

4. API Setup:
   - Configure valid API endpoints in `backend.py` and `backend_with_tkinter.py`.

---

 Security Notes
- Ensure `GROQ_API_KEY` remains private.
- Protect private keys during the authentication process.

---

 License
This project is licensed under the MIT License. See the LICENSE file for details.
