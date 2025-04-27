SecretSafe: Secure Encryption & Decryption Web App 🔐
Overview
SecretSafe is a web app built with Streamlit and Python that allows users to securely encrypt and decrypt messages with three levels of encryption (Low, Medium, High). 
Users can also add password protection for extra security.

Features
Three Encryption Levels:
1.Low (Fast): Simple shift cipher.
2.Medium (Balanced): Symmetric encryption with Fernet.
3.High (Very Safe): Asymmetric encryption with RSA.

Password Protection: Optionally add a password during encryption and require it for decryption.

Cross-Device: Works on any device with a web browser.

Technologies Used
Streamlit: For building the web app.
Python: For app logic and encryption.
Fernet & RSA: For encryption.
Base64: For encoding and decoding data.

Usage
Encrypt: Enter a message, choose security level, and optionally set a password. The app will return the encrypted message.
Decrypt: Paste the encrypted message and enter the password (if set). The app will return the original message.
