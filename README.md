## TUGAS 4 KEAMANAN INFORMASI Kelas C

| Nama | NRP |
|-------------|---------|
| Thalyta Vius Pramesti | 5025231055 |
| Aqila Zahira Naia Puteri Arifin | 5025231138 |
---

## Cara Menjalankan Program

Program ini adalah sistem messaging terenkripsi menggunakan DES untuk enkripsi pesan dan RSA untuk key exchange.

### Prerequisites
- Python 3.x
- Tidak ada library external yang diperlukan (menggunakan built-in modules)

### Langkah-Langkah Menjalankan:

#### 1. **Buka Terminal/Command Prompt Pertama - Jalankan Server**
```bash
python des_server_rsa.py
```
Output yang akan muncul:
```
[SERVER] Running on 0.0.0.0:5555
[SERVER] Waiting for connections...
```

#### 2. **Buka Terminal/Command Prompt Kedua - Jalankan Client Pertama**
```bash
python des_client_rsa.py
```
Program akan meminta input:
```
Enter server IP: 127.0.0.1
Enter your name: Alice
```
Isi IP server (gunakan `127.0.0.1` untuk localhost) dan nama klien.

#### 3. **Buka Terminal/Command Prompt Ketiga - Jalankan Client Kedua (atau lebih)**
```bash
python des_client_rsa.py
```
Ulangi langkah yang sama dengan nama berbeda:
```
Enter server IP: 127.0.0.1
Enter your name: Bob
```

#### 4. **Mulai Chat**
Setiap client dapat mengirim pesan terenkripsi ke client lain melalui server.
- Ketik pesan dan tekan Enter untuk mengirim
- Pesan akan dienkripsi menggunakan DES sebelum dikirim
- Server akan relay pesan ke client lain
- Client penerima akan mendekripsi pesan secara otomatis

### File Descriptions:
- `des_server_rsa.py` - Server yang mengelola komunikasi antar client
- `des_client_rsa.py` - Client untuk connect ke server dan chat
- `des_core.py` - Implementasi algoritma DES untuk enkripsi
- `rsa_core.py` - Implementasi algoritma RSA untuk key exchange
- `signature_core.py` - Implementasi digital signature

### Untuk Menghentikan Program:
- Tekan `Ctrl+C` di setiap terminal untuk menghentikan server/client
