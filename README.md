# Secret Notes

Python + Tkinter arayüzüyle metinleri güvenli şekilde saklayıp geri getirebileceğiniz küçük bir uygulama.

## Özellikler  
- Kullanıcıdan alınan düz metni AES-Fernet ile şifreler  
- Oluşan “salt+token” base64 string’ini tek bir dosyaya (`SecretNotes.txt`) başlıkla birlikte alt alta ekler  
- Şifreli metni ve parolayı girerek orijinal metne yeniden erişim sağlar  

## Gereksinimler  
- Python 3.8+  
- `cryptography` kütüphanesi (`pip install cryptography`)  
- Standart `tkinter` modülü  

## Kurulum & Çalıştırma  
1. Depoyu klonlayın veya dosyaları indirin  
2. Gerekliyse sanal ortam oluşturup aktifleştirin  
3. Gerekli paketleri yükleyin:  
   pip install cryptography
   
Uygulamayı çalıştırın:
python SecretNotes.py

Kullanım
Title: Kısa bir başlık girin (örn. “ödev”).
Secret: Gizlemek istediğiniz metni yazın.
Master Key: Şifreleme için parola girin.
Save & Encrypt: Metni şifreleyip SecretNotes.txt’e ekler.
Decrypt: Üstteki alana şifreli base64 string’i yapıştırıp aynı parolayla çözün.

SecretNotes.txt dosyasındaki her giriş iki satırdan oluşur:
Başlık
salt+token_base64
