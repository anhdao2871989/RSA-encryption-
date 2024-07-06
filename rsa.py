import tkinter as tk
from tkinter import ttk, scrolledtext
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1

class RSAEncryptionTool:
    def __init__(self, master):
        self.master = master
        master.title("RSA Encryption/Decryption Tool")
        master.geometry("1500x750")  # Adjusted window size

        self.public_key = None
        self.private_key = None

        self.create_widgets()

    def create_widgets(self):
        # Create the main frame with a canvas for scrolling
        main_frame = ttk.Frame(self.master)
        main_frame.pack(fill="both", expand=True)

        canvas = tk.Canvas(main_frame)
        canvas.pack(side="left", fill="both", expand=True)

        # scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        # scrollbar.pack(side="right", fill="y")

        # canvas.configure(yscrollcommand=scrollbar.set)
        # canvas.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        main_canvas = tk.Frame(canvas)
        canvas.create_window((0, 0), window=main_canvas, anchor="nw")

        # RSA Key Generation section
        key_frame = ttk.LabelFrame(main_canvas, text="Create RSA public / private keys")
        key_frame.pack(pady=10, padx=20, fill="x")

        generate_button_frame = ttk.Frame(key_frame)
        generate_button_frame.pack(side="left", padx=10)  # Center the generate button frame

        generate_button = ttk.Button(generate_button_frame, text="Generate Keys", command=self.generate_keys)
        generate_button.pack()

        key_display_frame = ttk.Frame(key_frame)
        key_display_frame.pack(pady=10, fill="x")

        public_key_label = ttk.Label(key_display_frame, text="Public Key", font=("Arial", 12, "bold"))
        public_key_label.pack(side="left", padx=10)

        self.public_key_text = scrolledtext.ScrolledText(key_display_frame, width=60, height=8, font=("Courier", 10), state="disabled")
        self.public_key_text.pack(side="left", padx=10, fill="both", expand=True)

        private_key_label = ttk.Label(key_display_frame, text="Private Key", font=("Arial", 12, "bold"))
        private_key_label.pack(side="left", padx=10)

        self.private_key_text = scrolledtext.ScrolledText(key_display_frame, width=60, height=8, font=("Courier", 10), state="disabled")
        self.private_key_text.pack(side="left", padx=10, fill="both", expand=True)

        # Encryption/Decryption section
        crypt_frame = ttk.LabelFrame(main_canvas, text="RSA Encryption / Decryption")
        crypt_frame.pack(pady=10, padx=20, fill="x")

        input_frame = ttk.Frame(crypt_frame)
        input_frame.pack(pady=10, fill="x")

        message_label = ttk.Label(input_frame, text="Message", font=("Arial", 12, "bold"))
        message_label.pack(side="left", padx=10)

        self.message_text = scrolledtext.ScrolledText(input_frame, width=60, height=8, font=("Arial", 12))
        self.message_text.pack(side="left", padx=10, fill="both", expand=True)

        input_label = ttk.Label(input_frame, text="Encrypted Message", font=("Arial", 12, "bold"))
        input_label.pack(side="left", padx=10)

        self.input_text = scrolledtext.ScrolledText(input_frame, width=60, height=8, font=("Arial", 12))
        self.input_text.pack(side="left", padx=10, fill="both", expand=True)

        button_frame = ttk.Frame(crypt_frame)
        button_frame.pack(pady=10, fill="x", anchor="center")  # Center the button frame

        encrypt_button = ttk.Button(button_frame, text="Encrypt", command=self.encrypt_message)
        encrypt_button.pack(side="left", padx=10, expand=True)

        decrypt_button = ttk.Button(button_frame, text="Decrypt", command=self.decrypt_message)
        decrypt_button.pack(side="left", padx=10, expand=True)

        output_label = ttk.Label(crypt_frame, text="Decrypted Text", font=("Arial", 12, "bold"))
        output_label.pack(anchor="w", pady=10)

        self.output_text = scrolledtext.ScrolledText(crypt_frame, width=120, height=8, font=("Arial", 12))
        self.output_text.pack(pady=10, fill="x", expand=True)

        # Error/Success Handling
        self.error_label = ttk.Label(main_canvas, text="", foreground="red", font=("Arial", 12))
        self.error_label.pack(pady=10, padx=20)

    def generate_keys(self):
        """
        Generate a new RSA key pair and display the public and private keys in the respective text boxes.
        """
        # Generate a new RSA private key and derive the public key from it
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        # Display the generated public and private keys in the respective text boxes
        self.public_key_text.config(state="normal")
        self.public_key_text.delete("1.0", tk.END)
        self.public_key_text.insert("1.0", self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode())
        self.public_key_text.config(state="disabled")

        self.private_key_text.config(state="normal")
        self.private_key_text.delete("1.0", tk.END)
        self.private_key_text.insert("1.0", self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode())
        self.private_key_text.config(state="disabled")

    def encrypt_message(self):
        """
        Encrypt the message entered in the message text box using the public key and OAEP padding scheme.
        Display the encrypted message in hexadecimal format in the output text box.
        """
        message = self.message_text.get("1.0", tk.END).strip()

        # Check if a public key is available and a message is entered
        if message and self.public_key:
            try:
                # Set up the OAEP padding scheme with SHA-256 hash function and MGF1 mask generation function
                oaep_padding = OAEP(
                    mgf=MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )

                # Encrypt the message using the public key and OAEP padding
                encrypted_message = self.public_key.encrypt(
                    message.encode(),
                    oaep_padding
                )

                # Display the encrypted message in hexadecimal format in the output text box
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert("1.0", encrypted_message.hex())
                self.error_label.config(text="")
            except Exception as e:
                # Display any encryption error in the error label
                self.error_label.config(text=f"Encryption error: {e}")
        else:
            # Display an error message if keys are not generated or no message is entered
            self.error_label.config(text="Please generate keys and enter a message to encrypt.")

    def decrypt_message(self):
        """
        Decrypt the encrypted message entered in the input text box using the private key and OAEP padding scheme.
        Display the decrypted message in the output text box.
        """
        encrypted_message = self.input_text.get("1.0", tk.END).strip()

        # Check if a private key is available and an encrypted message is entered
        if encrypted_message and self.private_key:
            try:
                # Set up the OAEP padding scheme with SHA-256 hash function and MGF1 mask generation function
                oaep_padding = OAEP(
                    mgf=MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )

                # Decrypt the message using the private key and OAEP padding
                decrypted_message = self.private_key.decrypt(
                    bytes.fromhex(encrypted_message),
                    oaep_padding
                ).decode()

                # Display the decrypted message in the output text box
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert("1.0", decrypted_message)
                self.error_label.config(text="")
            except Exception as e:
                # Display any decryption error in the error label
                self.error_label.config(text=f"Decryption error: {e}")
        else:
            # Display an error message if keys are not generated or no encrypted message is entered
            self.error_label.config(text="Please generate keys and enter an encrypted message to decrypt.")

# Create the main window and run the application
root = tk.Tk()
app = RSAEncryptionTool(root)
root.mainloop()