import streamlit as st
import hashlib
import docx
from io import BytesIO
import speech_recognition as sr
import os

# Create an uploads directory if it doesn't exist
if not os.path.exists("uploads"):
    os.makedirs("uploads")

def encrypt_doc(doc_content):
    """Encrypts the content of a docx file using SHA-256 hashing.

    Args:
        doc_content (bytes): The content of the docx file as bytes.

    Returns:
        str: A string containing the SHA-256 hash of the document content. Returns None on error.
    """
    try:
        hash_object = hashlib.sha256(doc_content)
        hashed_content = hash_object.hexdigest()
        return hashed_content
    except Exception as e:
        st.error(f"Encryption Error: {e}")  # Display error in Streamlit
        return None

def decrypt_doc(hashed_content, doc_content):
    """
    Checks if the hash of the doc content matches the provided hash and returns the original content.
    This is more of a validation than decryption, as SHA256 is not reversible.

    Args:
        hashed_content (str): The SHA-256 hash of the document.
        doc_content (bytes): The original document content in bytes.

    Returns:
        bytes: The original doc_content if the hash matches, otherwise None.
    """
    try:
        hash_object = hashlib.sha256(doc_content)
        calculated_hash = hash_object.hexdigest()
        if calculated_hash == hashed_content:
            return doc_content
        else:
            st.error("Decryption Error: Hash verification failed. Document may be corrupted.")
            return None
    except Exception as e:
        st.error(f"Decryption Error: {e}")
        return None

def extract_doc_content(doc_content):
    """Extracts the content of a docx file and returns it as a string.

    Args:
        doc_content (bytes): The content of the docx file as bytes.

    Returns:
        str: The extracted text content of the document.
    """
    try:
        doc = docx.Document(BytesIO(doc_content))  # Load from bytes
        full_text = []
        for para in doc.paragraphs:
            full_text.append(para.text)
        return "\n".join(full_text)  # Return as a single string
    except docx.opc.exceptions.PackageNotFoundError as e:  # Correctly catch specific docx exception
        st.error(f"Error: Could not open or process the document. It may be corrupted or not a valid docx file. Details: {e}")
        return None
    except Exception as e:
        st.error(f"Error extracting doc content: {e}")
        return None

def recognize_voice():
    """Recognizes voice input and returns the recognized text."""
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        st.write("Listening...")
        audio = recognizer.listen(source)
        try:
            text = recognizer.recognize_google(audio)
            st.write(f"Recognized: {text}")
            return text.lower()
        except sr.UnknownValueError:
            st.error("Sorry, I could not understand the audio.")
            return None
        except sr.RequestError as e:
            st.error(f"Could not request results from Google Speech Recognition service; {e}")
            return None

def main():
    st.title("Document Encryption/Decryption with Hashing and Voice Recognition")

    uploaded_file = st.file_uploader("Choose a DOCX file", type=["docx"])

    if uploaded_file is not None:
        # Save the uploaded file to the uploads directory
        file_path = os.path.join("uploads", uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        st.success(f"File '{uploaded_file.name}' uploaded and saved successfully!")

        # Read the file content
        doc_content = uploaded_file.read()

        if "hashed_content" not in st.session_state:
            st.session_state["hashed_content"] = None  # Initialize state

        if "original_content" not in st.session_state:
            st.session_state["original_content"] = doc_content

        if "encryption_status" not in st.session_state:
            st.session_state["encryption_status"] = "none"  # Start with no encryption/decryption

        if st.session_state["encryption_status"] == "none":
            st.write("Click the button below and say 'encrypt' to encrypt the document.")
            if st.button("Start Voice Command for Encryption"):
                command = recognize_voice()
                if command and "encrypt" in command:
                    st.session_state["hashed_content"] = encrypt_doc(st.session_state["original_content"])
                    if st.session_state["hashed_content"]:
                        st.session_state["encryption_status"] = "encrypted"
                        st.success("Document encrypted successfully!")
                        st.rerun()  # Refresh the app to show the encrypted view
                else:
                    st.error("Voice command not recognized. Please say 'encrypt'.")

        elif st.session_state["encryption_status"] == "encrypted":
            st.subheader("Encrypted Document (SHA-256 Hash):")
            st.write(st.session_state["hashed_content"])

            st.write("Click the button below and say 'decrypt' to decrypt the document.")
            if st.button("Start Voice Command for Decryption"):
                command = recognize_voice()
                if command and "decrypt" in command:
                    decrypted_content = decrypt_doc(st.session_state["hashed_content"], st.session_state["original_content"])
                    if decrypted_content:  # If decryption was successful
                        st.session_state["encryption_status"] = "decrypted"
                        st.success("Document decrypted successfully!")
                        st.rerun()  # Refresh app to display original content
                    else:
                        st.error("Decryption Failed: Could not verify or restore the original document. The hash might be mismatched.")
                else:
                    st.error("Voice command not recognized. Please say 'decrypt'.")

        elif st.session_state["encryption_status"] == "decrypted":
            st.subheader("Original Document Content:")
            doc_text = extract_doc_content(st.session_state["original_content"])
            if doc_text:
                st.text_area("Document Content", value=doc_text, height=300, key="original_doc_text", disabled=True)

if __name__ == "__main__":
    main()