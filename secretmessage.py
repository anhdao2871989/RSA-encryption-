import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
# Generate RSA keys
(pubkey, privkey) = RSA.generate(512, poolsize=8)


def encrypt_message():
    message = input_text.get("1.0", "end-1c")
    if message:
        try:
            encrypted_message = rsa.encrypt(message.encode(), public_key)
            output_text.delete("1.0", "end")
            output_text.insert("1.0", encrypted_message)
        except Exception as e:
            error_label.config(text=f"Encryption error: {e}")
    else:
        error_label.config(text="Please enter a message to encrypt.")

def decrypt_message():
    encrypted_message = input_text.get("1.0", "end-1c")
    if encrypted_message:
        try:
            decrypted_message = rsa.decrypt(encrypted_message.encode(), private_key).decode()
            output_text.delete("1.0", "end")
            output_text.insert("1.0", decrypted_message)
        except Exception as e:
            error_label.config(text=f"Decryption error: {e}")
    else:
        error_label.config(text="Please enter an encrypted message to decrypt.")

def save_encrypted_message():
    encrypted_message = output_text.get("1.0", "end-1c")
    if encrypted_message:
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "wb") as file:
                file.write(encrypted_message.encode())
            success_label.config(text="Encrypted message saved to file.")
    else:
        error_label.config(text="No encrypted message to save.")

def save_public_key():
    file_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem")])
    if file_path:
        with open(file_path, "wb") as file:
            file.write(rsa.save_pubkey(public_key))
        success_label.config(text="Public key saved to file.")

def save_private_key():
    file_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem")])
    if file_path:
        with open(file_path, "wb") as file:
            file.write(rsa.save_privkey(private_key))
        success_label.config(text="Private key saved to file.")

def load_public_key():
    file_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
    if file_path:
        global public_key
        public_key = rsa.PublicKey.load_pkcs1(open(file_path, "rb").read())
        success_label.config(text="Public key loaded successfully.")

def load_private_key():
    file_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
    if file_path:
        global private_key
        private_key = rsa.PrivateKey.load_pkcs1(open(file_path, "rb").read())
        success_label.config(text="Private key loaded successfully.")

def main():
    global input_text, output_text, error_label, success_label

    root = tk.Tk()
    root.title("RSA Encryption")
    root.geometry("800x600")

    main_frame = ttk.Frame(root, padding=20)
    main_frame.pack(fill="both", expand=True)

    input_label = ttk.Label(main_frame, text="Input Message:")
    input_label.pack(anchor="w")

    input_text = tk.Text(main_frame, width=60, height=10, font=("Arial", 12))
    input_text.pack()

    encrypt_button = ttk.Button(main_frame, text="Encrypt", command=encrypt_message)
    encrypt_button.pack(pady=10)

    decrypt_button = ttk.Button(main_frame, text="Decrypt", command=decrypt_message)
    decrypt_button.pack(pady=10)

    output_label = ttk.Label(main_frame, text="Output:")
    output_label.pack(anchor="w")

    output_text = tk.Text(main_frame, width=60, height=10, font=("Arial", 12))
    output_text.pack()

    save_encrypted_button = ttk.Button(main_frame, text="Save Encrypted Message", command=save_encrypted_message)
    save_encrypted_button.pack(pady=10)

    save_public_key_button = ttk.Button(main_frame, text="Save Public Key", command=save_public_key)
    save_public_key_button.pack(pady=10)

    save_private_key_button = ttk.Button(main_frame, text="Save Private Key", command=save_private_key)
    save_private_key_button.pack(pady=10)

    load_public_key_button = ttk.Button(main_frame, text="Load Public Key", command=load_public_key)
    load_public_key_button.pack(pady=10)

    load_private_key_button = ttk.Button(main_frame, text="Load Private Key", command=load_private_key)
    load_private_key_button.pack(pady=10)

    error_label = ttk.Label(main_frame, text="", foreground="red")
    error_label.pack(pady=10)

    success_label = ttk.Label(main_frame, text="", foreground="green")
    success_label.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()