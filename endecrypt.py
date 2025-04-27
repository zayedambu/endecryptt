import streamlit as st
import base64
from cryptography.fernet import Fernet
import rsa

# --- Fixed Keys ---
SHIFT = 3
medium_key = Fernet.generate_key()
cipher_medium = Fernet(medium_key)
(public_key, private_key) = rsa.newkeys(512)

# --- Helper Functions ---
def encrypt_low(message):
    shifted = ''.join(chr((ord(char) + SHIFT) % 256) for char in message)
    encoded = base64.b64encode(shifted.encode()).decode()
    return encoded

def decrypt_low(encoded):
    decoded = base64.b64decode(encoded.encode()).decode()
    shifted_back = ''.join(chr((ord(char) - SHIFT) % 256) for char in decoded)
    return shifted_back

def encrypt_medium(message):
    return cipher_medium.encrypt(message.encode()).decode()

def decrypt_medium(token):
    return cipher_medium.decrypt(token.encode()).decode()

def encrypt_high(message):
    return base64.b64encode(rsa.encrypt(message.encode(), public_key)).decode()

def decrypt_high(ciphertext):
    decoded = base64.b64decode(ciphertext.encode())
    return rsa.decrypt(decoded, private_key).decode()

# --- Streamlit App ---
st.set_page_config(page_title="EnDecrypt", page_icon="🔐", layout="centered")

# --- Landing Page ---
if "page" not in st.session_state:
    st.session_state.page = "landing"

if st.session_state.page == "landing":
    st.markdown("<h1 style='text-align: center; font-size: 48px;'>🔐 Welcome to EnDecrypt</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; font-size: 20px;'>Encrypt and Decrypt Messages Securely 🚀</p>", unsafe_allow_html=True)
    st.image("https://media.giphy.com/media/HoffxyN8ghVuw/giphy.gif", width=800)
    if st.button("🚀 Let's Start!"):
        st.session_state.page = "main"

elif st.session_state.page == "main":
    st.markdown("<h1 style='text-align: center;'>🔒 EnDecrypt</h1>", unsafe_allow_html=True)
    st.divider()

    # --- Encryption Mode ---
    mode = st.sidebar.radio("Choose Mode", ["🔐 Encrypt", "🔓 Decrypt"])
    security = st.sidebar.selectbox("Choose Security Level (for Encryption)", ["Low (Fast)", "Medium (Balanced)", "High (Very Safe)"])

    if mode == "🔐 Encrypt":
        st.subheader("🔐 Encryption Mode")
        message = st.text_area("Enter your message here:")

        use_password = st.checkbox("🔑 Set a password for this message?")
        password = ""
        if use_password:
            password = st.text_input("Set your password:", type="password")

        if st.button("🔒 Encrypt Now"):
            if message:
                # Encrypt message
                if security == "Low (Fast)":
                    encrypted_message = encrypt_low(message)
                elif security == "Medium (Balanced)":
                    encrypted_message = encrypt_medium(message)
                elif security == "High (Very Safe)":
                    encrypted_message = encrypt_high(message)

                # Add security tag and password tag
                password_tag = "[PASS]" if use_password else "[NOPASS]"
                security_tag = ""
                if security == "Low (Fast)":
                    security_tag = "[LOW]"
                elif security == "Medium (Balanced)":
                    security_tag = "[MEDIUM]"
                elif security == "High (Very Safe)":
                    security_tag = "[HIGH]"

                result = security_tag + password_tag + (password if use_password else "") + "|" + encrypted_message

                st.success("✅ Encrypted Message:")
                st.code(result)

                st.download_button("⬇️ Download Encrypted Message", result, file_name="encrypted_message.txt")

                
            else:
                st.error("❌ Please enter a message to encrypt.")

    # --- Decryption Mode ---
    elif mode == "🔓 Decrypt":
        st.subheader("🔓 Decryption Mode")
        message = st.text_area("Paste the encrypted message here:")

        entered_password = st.text_input("Enter Password (if required):", type="password")

        if st.button("🔓 Decrypt Now"):
            if message:
                try:
                    # Extract tags
                    if message.startswith("[LOW]"):
                        security_tag = "LOW"
                        rest = message[5:]
                    elif message.startswith("[MEDIUM]"):
                        security_tag = "MEDIUM"
                        rest = message[8:]
                    elif message.startswith("[HIGH]"):
                        security_tag = "HIGH"
                        rest = message[6:]
                    else:
                        st.error("❌ Unknown security level.")
                        st.stop()

                    if rest.startswith("[PASS]"):
                        password_protected = True
                        rest = rest[6:]
                    elif rest.startswith("[NOPASS]"):
                        password_protected = False
                        rest = rest[8:]
                    else:
                        st.error("❌ Password info missing or corrupted.")
                        st.stop()

                    if password_protected:
                        password_end = rest.find("|")
                        actual_password = rest[:password_end]
                        encrypted_content = rest[password_end+1:]

                        if entered_password != actual_password:
                            st.error("❌ Incorrect password.")
                            
                            st.stop()
                    else:
                        encrypted_content = rest.split("|",1)[1]

                    # Now decrypt based on security level
                    if security_tag == "LOW":
                        decrypted_message = decrypt_low(encrypted_content)
                    elif security_tag == "MEDIUM":
                        decrypted_message = decrypt_medium(encrypted_content)
                    elif security_tag == "HIGH":
                        decrypted_message = decrypt_high(encrypted_content)

                    st.success("✅ Decrypted Message:")
                    st.code(decrypted_message)
                    

                except Exception as e:
                    st.error(f"❌ Decryption failed: {e}")
                
            else:
                st.error("❌ Please paste a message to decrypt.")

    st.divider()
    st.markdown("<small style='text-align: center; display: block;'>Made with ❤️ by AMBU</small>", unsafe_allow_html=True)
