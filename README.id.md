# SENTRIX

**CLI reconnaissance keamanan dan intelijen eksposur.**
*Pahami permukaannya. Verifikasi risikonya. Amankan sistemnya.*

**Bahasa:** [English](README.md) | Bahasa Indonesia

`v0.1.0` | Python 3.13+ | Lisensi MIT | local-first, tanpa API key

## Ringkasan

SENTRIX adalah alat command-line yang memeriksa header keamanan HTTP dari
sebuah URL, lalu mengubah hasilnya menjadi temuan (finding) terstruktur yang
disertai bukti. Analisisnya deterministik dan berjalan di mesin Anda sendiri:
tidak ada layanan AI, platform cloud, ataupun API key yang terlibat. Alat ini
ditujukan untuk pemeriksaan berulang selama pengembangan dan untuk asesmen
keamanan yang telah diotorisasi.

Header yang hilang adalah sebuah observasi, bukan bukti adanya kerentanan yang
bisa dieksploitasi. Relevansi sebuah header bergantung pada aplikasi,
deployment, dan threat model-nya, dan SENTRIX melaporkannya dengan cara itu.

## Fitur

- **Pemeriksaan header keamanan HTTP.** Lima aturan mencakup
  Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options,
  Referrer-Policy, dan Permissions-Policy. Header yang tidak ada atau kosong
  dihitung sebagai temuan.
- **Pemeriksaan nilai header.** Enam aturan tambahan menilai header yang sudah
  ada: `max-age` HSTS yang lemah, CSP yang mengizinkan script inline/eval atau
  dari origin mana pun, nilai `nosniff` yang salah, Referrer-Policy yang
  membocorkan URL lengkap, serta pembocoran versi atau teknologi pada `Server`
  dan `X-Powered-By`. Nilai header hanya diperiksa, tidak pernah disimpan di
  temuan, laporan, maupun riwayat.
- **Temuan berbasis bukti.** Setiap temuan membawa rule id, bukti
  pendukungnya, label confidence, saran perbaikan, dan fingerprint yang stabil.
  Temuan di-deduplikasi dan diurutkan secara deterministik.
- **Kebijakan aturan yang bisa dikonfigurasi.** Matikan aturan, ubah
  severity-nya, dan gagalkan run CI di atas ambang tertentu, semuanya dari satu
  file TOML kecil.
- **Tiga format laporan.** JSON, SARIF 2.1.0, dan halaman HTML mandiri, semuanya
  dirender dari laporan yang sama.
- **Riwayat scan.** Simpan scan ke database SQLite lokal dan bandingkan dua scan
  mana pun.
- **Bawaan yang aman.** URL harus absolut `http`/`https`; request memiliki
  timeout 8 detik dan mengikuti paling banyak 5 redirect; nilai header respons
  tidak pernah ditulis ke laporan.

## Persyaratan

- Python 3.13 atau lebih baru, dan pip
- Git (opsional, disarankan untuk pengembangan)
- Akses internet untuk target remote

SENTRIX dikembangkan di Windows 11 dan di Kali Linux melalui WSL.

## Instalasi

Windows PowerShell:

```powershell
git clone https://github.com/CANDRA2006/sentrix.git
cd sentrix
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Kali Linux / WSL:

```bash
git clone https://github.com/CANDRA2006/sentrix.git
cd sentrix
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Penggunaan

```bash
sentrix --help
sentrix --version
sentrix check https://example.com
sentrix check https://example.com --timeout 15 --max-redirects 3
sentrix check https://example.com --output reports/example.json
sentrix check https://example.com -o reports/example.sarif --format sarif
sentrix check https://example.com -o reports/example.html --format html
sentrix check https://example.com --save
sentrix check https://example.com --config sentrix.toml --fail-on MEDIUM
sentrix rules --config sentrix.toml
sentrix history
sentrix compare 1 2
```

`check` adalah subcommand yang wajib ditulis. Exit code:

| Kode | Arti |
|---|---|
| `0` | Scan berjalan. Temuan tidak mengubah kode ini kecuali `--fail-on` dipakai. |
| `1` | Scan tidak dapat diselesaikan: kegagalan jaringan, timeout, redirect berulang tanpa akhir, atau file laporan atau riwayat yang tidak bisa ditulis. |
| `2` | Input tidak valid: URL salah, nilai opsi tidak dikenal, atau file kebijakan tidak valid. |
| `3` | Gate `--fail-on` gagal: ada temuan pada atau di atas ambang. |

## Contoh output

Berikut output nyata dari run terhadap server uji lokal yang satu-satunya header
keamanannya adalah `X-Content-Type-Options`. Temuan untuk target Anda sendiri
bergantung pada header respons target tersebut.

```text
SENTRIX :: HTTP POSTURE CHECK
Target: http://127.0.0.1:8793/

HTTP status: 200 | Redirects: 0
                      HTTP Security Posture                      
┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Rule ID  ┃ Severity ┃ Finding                                 ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HTTP-001 │ MEDIUM   │ Content Security Policy tidak ditemukan │
│ HTTP-004 │ LOW      │ Referrer-Policy tidak ditemukan         │
│ HTTP-005 │ INFO     │ Permissions-Policy tidak ditemukan      │
└──────────┴──────────┴─────────────────────────────────────────┘

Findings: 3
```

Judul aturan, rekomendasi, dan banyak pesan di terminal saat ini berbahasa
Indonesia; lokalisasi (pilihan bahasa output) belum tersedia. Key pada laporan
JSON berbahasa Inggris.

## Aturan keamanan

| Rule ID | Header | Severity bawaan | Catatan |
|---|---|---|---|
| `HTTP-001` | `Content-Security-Policy` | MEDIUM | Mengatur sumber konten yang boleh dipakai sebuah halaman. |
| `HTTP-002` | `Strict-Transport-Security` | MEDIUM | Hanya dievaluasi untuk respons HTTPS. |
| `HTTP-003` | `X-Content-Type-Options` | LOW | Membantu mencegah MIME-type sniffing. |
| `HTTP-004` | `Referrer-Policy` | LOW | Mengatur informasi referrer yang dikirim browser. |
| `HTTP-005` | `Permissions-Policy` | INFO | Mengatur kemampuan browser tertentu. |
| `HTTP-101` | `Strict-Transport-Security` | LOW | Ada, tetapi `max-age` hilang, nol, atau kurang dari 180 hari. Hanya dievaluasi untuk respons HTTPS. |
| `HTTP-102` | `Content-Security-Policy` | MEDIUM | Kebijakan script efektif (`script-src`, atau `default-src`) mengizinkan `'unsafe-inline'` tanpa nonce/hash, `'unsafe-eval'`, `*`, `http:`, `https:`, atau `data:`. Bersifat heuristik, sehingga confidence-nya MEDIUM. |
| `HTTP-103` | `X-Content-Type-Options` | LOW | Ada, tetapi nilainya bukan `nosniff`. |
| `HTTP-104` | `Referrer-Policy` | LOW | Kebijakan efektif (yang terakhir) adalah `unsafe-url` atau `no-referrer-when-downgrade`. |
| `HTTP-201` | `Server` | LOW | Nilainya memuat nomor versi. |
| `HTTP-202` | `X-Powered-By` | LOW | Header ini ada. |

Aturan `HTTP-001` sampai `HTTP-005` melaporkan header yang hilang. Aturan
`HTTP-101` ke atas melaporkan header yang ada tetapi lemah atau membocorkan
informasi. Aturan-aturan itu memakai tipe evidence `weak_header_value` dan
`information_disclosure`, sehingga fingerprint-nya tidak pernah sama dengan
temuan header-hilang. Setiap aturan bisa dimatikan atau di-re-triase lewat
file kebijakan.

Label severity adalah label triase berbasis aturan, bukan skor CVSS. Jalankan
`sentrix rules` untuk melihat daftar yang sama, termasuk apa yang diubah oleh
file kebijakan.

## Format laporan

`--output` menulis laporan ke file. `--format` memilih formatnya (`json`,
`sarif`, atau `html`; tidak peka huruf besar/kecil) dan bawaannya `json`, yaitu
laporan yang sama seperti sebelumnya. `--format` tanpa `--output` ditolak
sebelum request apa pun dikirim.

| Format | Dipakai untuk |
|---|---|
| `json` | Laporan lengkap yang bisa dibaca mesin. |
| `sarif` | SARIF 2.1.0, untuk viewer SARIF dan alat yang mengagregasi temuan. |
| `html` | Satu halaman mandiri untuk dibaca, dilampirkan ke tiket, atau dicetak. |

Ketiganya dirender dari laporan yang sama, sehingga selalu konsisten.

- **SARIF** memetakan severity ke `level` (`HIGH` menjadi `error`, `MEDIUM`
  menjadi `warning`, `LOW` dan `INFO` menjadi `note`); label aslinya tetap ada
  di `properties` tiap hasil. Skor `security-severity` tidak diisi, karena
  severity SENTRIX bukan skor CVSS. Setiap hasil membawa fingerprint yang sama
  dengan yang dipakai `compare`. Lokasi sebuah hasil adalah URL yang di-scan,
  bukan file di sebuah repositori, sehingga alat yang memetakan alert ke file
  sumber (misalnya GitHub code scanning) mungkin tidak bisa menempatkannya.
- **HTML** hanya memakai CSS inline: tanpa script, tanpa resource eksternal, dan
  Content-Security-Policy yang ketat. Setiap nilai di-escape untuk HTML. Tampilan
  mengikuti pengaturan terang/gelap sistem dan tercetak dengan rapi.
- **URL** pada laporan SARIF dan HTML dibersihkan dari userinfo, query string,
  dan fragment. Laporan JSON tetap menyimpan URL persis seperti yang Anda
  ketik, seperti sebelumnya, jadi jangan dibagikan jika query string-nya
  membawa token.
- Tidak ada format yang memuat nilai header respons.
- Kebijakan aturan yang dipakai sebuah scan (lihat di bawah) menjadi bagian dari
  setiap laporan: blok `policy` pada JSON (report schema `1.1`), bagian
  "Kebijakan" pada halaman HTML, dan `policy` pada run properties SARIF.

## Kebijakan aturan

File kebijakan (policy) mengubah aturan bawaan mana yang berjalan, seberapa
parah severity-nya, dan kapan `check` dianggap gagal. Bentuknya file TOML
kecil, dan hanya dibaca saat Anda memintanya:

```toml
# sentrix.toml
[policy]
fail_on = "MEDIUM"   # exit code 3 jika ada temuan MEDIUM atau lebih tinggi

[rules.HTTP-001]
severity = "HIGH"    # triase ulang sebuah aturan: HIGH, MEDIUM, LOW, atau INFO

[rules.HTTP-005]
enabled = false      # aturan ini tidak dievaluasi sama sekali
```

```bash
sentrix rules                                  # daftar rule id, header, severity
sentrix rules --config sentrix.toml            # sama, dengan kebijakan diterapkan
sentrix check https://example.com --config sentrix.toml
sentrix check https://example.com --fail-on HIGH   # gate tanpa file
```

| Pengaturan | Efek |
|---|---|
| `[policy] fail_on` | `check` keluar dengan kode `3` jika ada temuan pada atau di atas severity ini. `--fail-on` di command line menimpanya. Tanpa keduanya, temuan tidak pernah mengubah exit code. |
| `[rules.ID] enabled = false` | Aturan tidak dievaluasi. |
| `[rules.ID] severity` | Mengganti severity aturan. Temuannya tetap memakai fingerprint yang sama, sehingga `compare` menampilkan perubahan severity, bukan temuan baru. |

Cara kerjanya:

- **Hanya jika diminta.** Berikan `--config PATH` (atau `-c`), atau setel
  `SENTRIX_CONFIG`; flag lebih diutamakan. File `sentrix.toml` di direktori
  saat ini tidak pernah terbaca dengan sendirinya, sehingga file yang
  tersasar tidak bisa mengubah hasil.
- **Ketat.** Key tak dikenal, rule id tak dikenal, tipe yang salah, dan severity
  yang tidak valid adalah error (exit code `2`, sebelum request apa pun),
  karena typo yang diam-diam diabaikan terlihat persis seperti kebijakan yang
  berjalan. `sentrix rules --config FILE` memeriksa sebuah file tanpa
  melakukan scan. Gunakan `sentrix rules` untuk melihat rule id yang valid.
- **Penekanan temuan tidak pernah diam-diam.** `check` mencetak kebijakan yang
  aktif, dan aturan yang dimatikan serta override severity dicatat di laporan
  dan di riwayat. Anggap aturan yang dimatikan sebagai "tidak dievaluasi",
  bukan "lulus". Jika sebuah kebijakan mematikan semua aturan, `check`
  memperingatkan bahwa tidak ada yang diperiksa dan pesan gate menyatakannya,
  bukan melaporkan lulus biasa.
- **Gate dijalankan paling akhir.** Saat `--fail-on` gagal, laporan dan entri
  riwayat tetap ditulis terlebih dahulu, sehingga run CI yang gagal tetap
  meninggalkan buktinya.
- **Hanya nama file yang dicatat**, bukan direktorinya.
- **Batasan.** Hanya UTF-8 (BOM tidak masalah), maksimal 64 KiB, dan tidak
  boleh bersarang terlalu dalam secara berlebihan (dilaporkan sebagai file
  tidak valid). Kebijakan tidak bisa menambah aturan atau menjalankan kode.
  Di Windows PowerShell 5, `>` menulis UTF-16 yang ditolak; buat file di editor
  yang menyimpan UTF-8, atau tulis dengan `Set-Content -Encoding utf8`.

Run yang sama seperti di atas, dengan kebijakan dari contoh (`HTTP-001` dinaikkan
ke HIGH, `HTTP-005` dimatikan, gate di MEDIUM):

```text
SENTRIX :: HTTP POSTURE CHECK
Target: http://127.0.0.1:8793/
Kebijakan: sentrix.toml | nonaktif: HTTP-005 | severity: HTTP-001=HIGH | gagal 
jika >= MEDIUM

HTTP status: 200 | Redirects: 0
                      HTTP Security Posture                      
┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Rule ID  ┃ Severity ┃ Finding                                 ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HTTP-001 │ HIGH     │ Content Security Policy tidak ditemukan │
│ HTTP-004 │ LOW      │ Referrer-Policy tidak ditemukan         │
└──────────┴──────────┴─────────────────────────────────────────┘

Findings: 2
Gate gagal: ada temuan dengan severity MEDIUM atau lebih tinggi.
```

Prosesnya keluar dengan kode `3`.

## Riwayat scan

`check --save` menyimpan hasil ke database SQLite lokal agar scan bisa
didaftar dan dibandingkan dari waktu ke waktu. Tidak ada yang disimpan kecuali
`--save` diberikan.

```bash
sentrix check https://example.com --save   # mencetak "Scan tersimpan di riwayat: #1"
sentrix history                            # terbaru dulu; --limit/-n N (1-500)
sentrix compare 1 2                        # id lama, lalu id baru
```

`compare OLD NEW` mencocokkan temuan berdasarkan fingerprint (rule id + bukti,
sehingga mengubah redaksi judul tidak membuat temuan tampak baru) dan
melaporkan temuan yang baru, teratasi, tetap, atau berubah severity-nya.
Membandingkan scan dari target yang berbeda mencetak peringatan, begitu pula
membandingkan scan yang berjalan dengan kebijakan aturan yang berbeda, karena
aturan yang dimatikan tampak "teratasi" padahal targetnya tidak berubah.
`--fail-on` bukan bagian dari perbandingan itu, karena tidak dapat mengubah
apa yang ditemukan sebuah scan. `compare` bersifat searah: menukar kedua id
menukar "baru" dan "teratasi".

```text
SENTRIX :: COMPARE #1 -> #2
Lama: http://127.0.0.1:8793/ (2026-10-31T12:11:01.033209+00:00)
Baru: http://127.0.0.1:8793/ (2026-10-31T12:11:01.209701+00:00)

Peringatan: kedua scan memakai kebijakan aturan yang berbeda (lama: bawaan; 
baru: nonaktif: HTTP-005; severity: HTTP-001=HIGH). Temuan BARU, TERATASI, atau 
BERUBAH bisa jadi hanya akibat aturan yang dinonaktifkan atau diubah 
severity-nya, bukan karena targetnya berubah.

TERATASI  HTTP-005 [INFO] Permissions-Policy tidak ditemukan
BERUBAH   HTTP-001 MEDIUM -> HIGH Content Security Policy tidak ditemukan

Baru: 0 | Teratasi: 1 | Berubah severity: 1 | Tetap: 1
```

Database secara bawaan berada di `~/.sentrix/history.db`. Ganti dengan
`--db PATH` atau variabel lingkungan `SENTRIX_DB`. File database baru dibuat
hanya-pemilik (`0600`) di dalam direktori `0700` pada sistem POSIX.

Yang disimpan: target dan URL akhir, timestamp, status HTTP, versi tool,
kebijakan aturan yang dipakai scan (aturan yang dimatikan dan override
severity, bukan path file), serta temuan (rule id, judul, severity,
confidence, nama header). Yang **tidak** disimpan: nilai header respons, serta
userinfo, query string, dan fragment pada URL. Path URL disimpan apa adanya,
jadi hindari men-scan URL yang path-nya sendiri memuat rahasia.

Schema riwayat diberi versi. Database dari SENTRIX yang lebih lama
ditingkatkan di tempat saat pertama kali dibuka (schema 1 ke 2 menambah kolom
policy; scan yang sudah ada tetap utuh dan dihitung sebagai "aturan bawaan"),
di dalam satu transaksi, sehingga peningkatan yang gagal membiarkan file
seperti semula. Pembukaan pertama itu membutuhkan akses tulis bahkan untuk
perintah baca-saja seperti `history` dan `compare`, jadi database lama pada
mount read-only harus dibuat bisa ditulis satu kali. Setelah peningkatan,
SENTRIX versi lama menolak file tersebut dan tidak mengubahnya, begitu pula
database yang ditulis dengan schema yang lebih baru. File SQLite yang bukan
riwayat SENTRIX tidak pernah diadopsi: tabelnya diperiksa sebelum peningkatan,
dan file yang tidak cocok dibiarkan tanpa perubahan. Cadangkan
`~/.sentrix/history.db` terlebih dahulu jika Anda ingin tetap bisa kembali ke
versi yang lebih lama.

## Cara kerja

```text
URL + opsi
     |
     v
Validasi input (URL, --format, file kebijakan)
     |
     v
HTTP request (httpx: timeout, batas redirect)
     |
     v
Aturan header (kebijakan diterapkan) --> Normalisasi (dedup, urut, fingerprint)
     |
     v
Satu dokumen laporan
     |
     +--> Tabel terminal
     +--> JSON / SARIF / HTML   (--output, --format)
     +--> Riwayat SQLite        (--save)  --> history, compare
```

| Modul | Peran |
|---|---|
| `cli.py` | Perintah Typer (`check`, `rules`, `history`, `compare`), penyusunan laporan, exit code |
| `rules.py` | Aturan header bawaan |
| `policy.py` | Kebijakan TOML: memuat, memvalidasi, menerapkannya ke aturan, gate |
| `models.py` | Model temuan bertipe beserta fingerprint-nya |
| `normalize.py` | Deduplikasi dan pengurutan deterministik |
| `reporting.py` | Exporter JSON, SARIF, dan HTML |
| `history.py` | Riwayat SQLite dan perbandingan scan |

## Pengujian

```bash
python -m pytest -v
```

## Penggunaan yang bertanggung jawab

SENTRIX ditujukan untuk asesmen keamanan yang telah diotorisasi, lingkungan
pengembangan, dan riset keamanan untuk tujuan edukasi.

- Hanya uji sistem yang Anda miliki atau yang secara eksplisit diizinkan
  untuk Anda uji, dan hormati cakupan serta kebijakan yang berlaku untuknya.
- Header yang hilang adalah observasi, bukan bukti kerentanan yang bisa
  dieksploitasi. Verifikasi dulu sebelum menganggap hasil sebagai masalah
  yang sudah terkonfirmasi.
- Label severity adalah label triase berbasis aturan, bukan skor CVSS.
- SENTRIX hanya memeriksa header respons. Alat ini tidak mengeksploitasi apa
  pun dan bukan asesmen keamanan yang menyeluruh.

## Keterbatasan keamanan yang diketahui

Hal berikut belum terselesaikan:

- Redirect diikuti tanpa memeriksa tujuannya. URL publik dapat mengarahkan ke
  `localhost`, alamat jaringan privat, atau alamat metadata cloud.
- Hostname tidak di-resolve atau dicek terhadap rentang alamat privat/reserved,
  dan URL yang sudah menunjuk ke alamat semacam itu diterima.
- Hanya status line dan header dari respons akhir yang dibaca; body-nya tidak
  pernah diunduh. httpx tetap membaca body setiap respons redirect perantara
  sebelum mengikutinya, dan itu tidak dibatasi ukurannya.

## Rencana

Belum tersedia pada rilis saat ini:

- Kontrol keamanan jaringan: cakupan target dan pemeriksaan alamat privat
  (lihat keterbatasan di atas)
- Mengimpor hasil dari alat keamanan lain
- Penjelasan temuan berbantuan AI yang opsional (analisis intinya akan tetap
  deterministik dan berjalan tanpanya)
- Workflow CI untuk test suite repositori ini

## Kontribusi

Kontribusi, laporan bug, dan saran sangat diterima.

1. Fork repositori dan buat feature branch.
2. Tambahkan tes untuk perilaku baru.
3. Jalankan `python -m pytest -v`.
4. Buka pull request yang menjelaskan perubahan dan implikasi keamanannya.

## Lisensi

Dirilis di bawah [Lisensi MIT](LICENSE).
