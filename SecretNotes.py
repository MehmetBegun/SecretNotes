import tkinter
from PIL import Image, ImageTk
import os, tkinter.messagebox as mb
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ui = tkinter.Tk()
ui.title("Secret Notes")
ui.configure(background= "blue")
ui.geometry("200x350")

pil_img = Image.open("SecretNotesGörseli.jpeg")
img = ImageTk.PhotoImage(pil_img)
image_label = tkinter.Label(ui, image=img, background="blue")
image_label.image = img
image_label.pack(side="top", fill="x", pady=5)

# ——— Anahtar türetme
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# ——— Şifreleme
def encrypt_text(plain: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(plain.encode("utf-8"))
    return base64.urlsafe_b64encode(salt + token).decode("utf-8")

# ——— Çözme
def decrypt_text(data_b64: str, password: str) -> str:
    data = base64.urlsafe_b64decode(data_b64)
    salt, token = data[:16], data[16:]
    key = derive_key(password, salt)
    return Fernet(key).decrypt(token).decode("utf-8")

# ——— Tek dosya yolu
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_FILE = os.path.join(BASE_DIR, "SecretNotes.txt")

def on_encrypt():
    title    = title_entry.get().strip()
    password = masterKey_entry.get().strip()
    secret   = secret_text.get("1.0", "end-1c").strip()
    if not title or not password or not secret:
        mb.showerror("Hata", "Başlık, parola ve mesaj gerekli.")
        return

    encrypted = encrypt_text(secret, password)
    with open(SECRETS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{title}\n{encrypted}\n\n")

    mb.showinfo("Tamam", f"Mesaj SecretNotes.txt dosyasına eklendi.")

def on_decrypt():
    # 1) Text widget’ından base64 şifreli metni al
    encrypted_b64 = secret_text.get("1.0", "end-1c").strip()
    password     = masterKey_entry.get().strip()

    if not encrypted_b64 or not password:
        mb.showerror("Hata", "Lütfen önce şifreli metni ve anahtarı girin.")
        return

    try:
        # 2) Base64 → salt+token bayt dizisi
        data = base64.urlsafe_b64decode(encrypted_b64.encode("utf-8"))
        salt, token = data[:16], data[16:]
        # 3) Aynı derive_key ile anahtarı oluştur
        key = derive_key(password, salt)
        # 4) Fernet ile decrypt et
        plain = Fernet(key).decrypt(token).decode("utf-8")
    except Exception as e:
        mb.showerror("Hata", f"Çözme başarısız: {e}")
        return

    # 5) Sonucu Text widget’ına yaz
    secret_text.delete("1.0", "end")
    secret_text.insert("1.0", plain)
    mb.showinfo("Başarılı", "Metin başarıyla çözüldü.")

title = tkinter.Label(ui,background= "blue",foreground= "black",text= "Enter your title",width= 30,height= 1)
title.pack(side="top",anchor="center")

title_entry = tkinter.Entry(ui)
title_entry.pack(side="top",pady=3,anchor="center")

secret = tkinter.Label(ui,background= "blue",foreground= "black",text= "Enter your secret",width= 30,height= 1)
secret.pack(side="top",anchor="center")

secret_text = tkinter.Text(ui,width=30,height=10,wrap="word")
secret_text.pack(side="top",pady=3,anchor="center")

masterKey = tkinter.Label(ui,background= "blue",foreground= "black",text= "Enter master key",width= 30,height= 1)
masterKey.pack(side="top",anchor="center")

masterKey_entry = tkinter.Entry(ui,width= 25)
masterKey_entry.pack(side="top",pady=3,anchor="center")

encrypt = tkinter.Button(foreground= "black",text= "Save & Encrypt",command= on_encrypt)
encrypt.pack(side="top",pady=5,anchor="center")

decrypt = tkinter.Button(foreground= "black",text= "Decrypt",command= on_decrypt)
decrypt.pack(side="top",pady=5,anchor="center")

title_entry.focus()

ui.mainloop()