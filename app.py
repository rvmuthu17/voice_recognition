import streamlit as st
import hashlib
import docx
from io import BytesIO

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

def display_doc_content(doc_content):
    """Displays the content of a docx file in Streamlit.

    Args:
        doc_content (bytes): The content of the docx file as bytes.
    """
    try:
        doc = docx.Document(BytesIO(doc_content))  # Load from bytes
        full_text = []
        for para in doc.paragraphs:
            full_text.append(para.text)
        st.write("\n".join(full_text))  # Display as a block of text in Streamlit
    except docx.opc.exceptions.PackageNotFoundError as e:  # Correctly catch specific docx exception
        st.error(f"Error: Could not open or process the document. It may be corrupted or not a valid docx file. Details: {e}")
    except Exception as e:
        st.error(f"Error displaying doc content: {e}")

def main():
    st.title("Document Encryption/Decryption with Hashing")

    uploaded_file = st.file_uploader("Choose a DOCX file", type=["docx"])

    if uploaded_file is not None:
        doc_content = uploaded_file.read()

        if "hashed_content" not in st.session_state:
            st.session_state["hashed_content"] = None  # Initialize state

        if "original_content" not in st.session_state:
            st.session_state["original_content"] = doc_content

        if "encryption_status" not in st.session_state:
            st.session_state["encryption_status"] = "decrypted"  # Start at decrypted state

        if st.session_state["encryption_status"] == "decrypted":
            st.subheader("Original Document Content:")
            display_doc_content(st.session_state["original_content"])  # Display original doc content
            encrypt_button = st.button("Encrypt Document")

            if encrypt_button:
                st.session_state["hashed_content"] = encrypt_doc(st.session_state["original_content"])
                if st.session_state["hashed_content"]:
                    st.session_state["encryption_status"] = "encrypted"
                    st.success("Document encrypted successfully!")
                    st.rerun()  # Refresh the app to show the encrypted view
        else:
            st.subheader("Encrypted Document (SHA-256 Hash):")
            st.write(st.session_state["hashed_content"])

            decrypt_button = st.button("Decrypt Document")  # More accurately, "Restore Document"

            if decrypt_button:
                decrypted_content = decrypt_doc(st.session_state["hashed_content"], st.session_state["original_content"])
                if decrypted_content:  # If decryption was successful
                    st.session_state["encryption_status"] = "decrypted"  # Set to decrypted to redisplay original document
                    st.success("Document decrypted successfully!")
                    st.rerun()  # Refresh app to display original content
                else:
                    st.error("Decryption Failed: Could not verify or restore the original document. The hash might be mismatched.")

if __name__ == "__main__":
    main()