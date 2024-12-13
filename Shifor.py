import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets
import base64


def generate_salt(size=16):
    return secrets.token_bytes(size)


def load_salt():
    try:
        with open("salt.salt", "rb") as salt_file:
            return salt_file.read()
    except FileNotFoundError:
        messagebox.showerror("Ошибка", "Файл соли не найден. Убедитесь, что вы создали соль перед расшифровкой.")
        return None


def derive_key(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())


def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    if load_existing_salt:
        salt = load_salt()
        if not salt:
            return None
    else:
        salt = generate_salt(salt_size)
        if save_salt:
            with open("salt.salt", "wb") as salt_file:
                salt_file.write(salt)

    derived_key = derive_key(salt, password)
    return base64.urlsafe_b64encode(derived_key)


def encrypt(filename, key):
    try:
        f = Fernet(key)
        with open(filename, "rb") as file:
            file_data = file.read()

        encrypted_data = f.encrypt(file_data)

        with open(filename, "wb") as file:
            file.write(encrypted_data)

        messagebox.showinfo("Успех", "Файл успешно зашифрован.")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка при шифровании: {e}")


def decrypt(filename, key):
    try:
        f = Fernet(key)
        with open(filename, "rb") as file:
            encrypted_data = file.read()

        decrypted_data = f.decrypt(encrypted_data)

        with open(filename, "wb") as file:
            file.write(decrypted_data)

        messagebox.showinfo("Успех", "Файл успешно расшифрован.")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка при расшифровке: {e}")


def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)


def handle_encrypt():
    file_path = file_entry.get()
    password = password_entry.get()
    if not file_path or not password:
        messagebox.showerror("Ошибка", "Укажите файл и пароль для шифрования.")
        return

    key = generate_key(password, save_salt=True)
    if key:
        encrypt(file_path, key)


def handle_decrypt():
    file_path = file_entry.get()
    password = password_entry.get()
    if not file_path or not password:
        messagebox.showerror("Ошибка", "Укажите файл и пароль для расшифровки.")
        return

    key = generate_key(password, load_existing_salt=True)
    if key:
        decrypt(file_path, key)



root = tk.Tk()
root.title("Шифрование и дешифрование файлов")


file_frame = tk.Frame(root)
file_frame.pack(pady=10)

file_label = tk.Label(file_frame, text="Файл:")
file_label.pack(side=tk.LEFT, padx=5)

file_entry = tk.Entry(file_frame, width=40)
file_entry.pack(side=tk.LEFT, padx=5)

file_button = tk.Button(file_frame, text="Выбрать", command=select_file)
file_button.pack(side=tk.LEFT, padx=5)


password_frame = tk.Frame(root)
password_frame.pack(pady=10)

password_label = tk.Label(password_frame, text="Пароль:")
password_label.pack(side=tk.LEFT, padx=5)

password_entry = tk.Entry(password_frame, show="*", width=40)
password_entry.pack(side=tk.LEFT, padx=5)


button_frame = tk.Frame(root)
button_frame.pack(pady=20)

encrypt_button = tk.Button(button_frame, text="Зашифровать", command=handle_encrypt)
encrypt_button.pack(side=tk.LEFT, padx=10)

decrypt_button = tk.Button(button_frame, text="Дешифровать", command=handle_decrypt)
decrypt_button.pack(side=tk.LEFT, padx=10)

root.mainloop()
