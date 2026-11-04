# Registrasi Karyawan (Netlify)

- `/`      : form registrasi untuk karyawan (bisa dibuka di semua HP)
- `/hrd`   : halaman HRD (login kata sandi): impor massal, cari data, buka berkas, unduh Excel

## Cara pasang (cara termudah, lewat GitHub)
1. Buat repository baru di GitHub, unggah SELURUH isi folder ini (termasuk folder `public` dan `netlify`).
2. Di Netlify: Add new site > Import an existing project > pilih repository tadi. Biarkan pengaturan build default (sudah diatur di netlify.toml). Klik Deploy.
3. Di Netlify: Site configuration > Environment variables, tambahkan:
   - `HRD_PASSWORD`  = kata sandi HRD (minimal 12 karakter)
   - `TOKEN_SECRET`  = teks acak panjang (bebas, jangan dibagikan)
4. Deploy ulang: Deploys > Trigger deploy > Deploy site.
5. Bagikan `https://NAMA-SITUS.netlify.app/` ke karyawan, dan `https://NAMA-SITUS.netlify.app/hrd` hanya ke HRD.

Catatan: drag-and-drop folder di Netlify TIDAK cocok karena fungsi server butuh paket @netlify/blobs.
Alternatif: pakai Netlify CLI (`npm i -g netlify-cli`, lalu `netlify deploy --prod`).

## Penyimpanan
Data dan berkas disimpan di Netlify Blobs (bawaan Netlify, tanpa akun database lain).
Data: store `karyawan` (kunci = NIK). Berkas: store `berkas` (kunci = NIK/jenis-berkas).
Cadangkan rutin lewat tombol "Unduh Excel" di halaman HRD.
