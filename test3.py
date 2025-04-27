# Save this as app.py
import streamlit as st
import base64
from cryptography.fernet import Fernet
import rsa

# ---------- Fixed Keys ----------
# Low Security Key
SHIFT = 3

# Medium Security Key (AES-like)
medium_key = Fernet.generate_key()
cipher_medium = Fernet(medium_key)

# High Security Key (RSA)
(public_key, private_key) = rsa.newkeys(512)

# ---------- Helper Functions ----------

# LOW Security (simple Caesar cipher + base64)
def encrypt_low(message):
    shifted = ''.join(chr((ord(char) + SHIFT) % 256) for char in message)
    encoded = base64.b64encode(shifted.encode()).decode()
    return encoded

def decrypt_low(encoded):
    decoded = base64.b64decode(encoded.encode()).decode()
    shifted_back = ''.join(chr((ord(char) - SHIFT) % 256) for char in decoded)
    return shifted_back

# MEDIUM Security (Fernet symmetric encryption)
def encrypt_medium(message):
    return cipher_medium.encrypt(message.encode()).decode()

def decrypt_medium(token):
    return cipher_medium.decrypt(token.encode()).decode()

# HIGH Security (RSA encryption)
def encrypt_high(message):
    return base64.b64encode(rsa.encrypt(message.encode(), public_key)).decode()

def decrypt_high(ciphertext):
    decoded = base64.b64decode(ciphertext.encode())
    return rsa.decrypt(decoded, private_key).decode()

# ---------- Streamlit App ----------

st.title("🔐 Encryption & Decryption App")

mode = st.sidebar.selectbox("Choose Mode", ["Encrypt", "Decrypt"])
security = st.sidebar.selectbox("Choose Security Level (for Encryption)", ["Low (Fast)", "Medium (Balanced)", "High (Very Safe)"])

if mode == "Encrypt":
    st.header("Encryption Mode")
    message = st.text_area("Enter your message:")
    if st.button("Encrypt"):
        if message:
            if security == "Low (Fast)":
                encrypted_message = encrypt_low(message)
                result = "[LOW]" + encrypted_message
            elif security == "Medium (Balanced)":
                encrypted_message = encrypt_medium(message)
                result = "[MEDIUM]" + encrypted_message
            elif security == "High (Very Safe)":
                encrypted_message = encrypt_high(message)
                result = "[HIGH]" + encrypted_message
            st.success("Encrypted Message:")
            st.code(result)
            st.info("🔔 Remember: The security level tag is attached automatically!")
        else:
            st.error("Please enter a message to encrypt.")

elif mode == "Decrypt":
    st.header("Decryption Mode")
    message = st.text_area("Enter the encrypted message (with tag):")
    if st.button("Decrypt"):
        if message:
            try:
                if message.startswith("[LOW]"):
                    real_message = message[5:]
                    result = decrypt_low(real_message)
                elif message.startswith("[MEDIUM]"):
                    real_message = message[8:]
                    result = decrypt_medium(real_message)
                elif message.startswith("[HIGH]"):
                    real_message = message[6:]
                    result = decrypt_high(real_message)
                else:
                    st.error("❌ Unknown or missing security level tag.")
                    result = None

                if result:
                    st.success("Decrypted Message:")
                    st.code(result)

            except Exception as e:
                st.error(f"Decryption failed: {e}")
        else:
            st.error("Please enter a message to decrypt.")
