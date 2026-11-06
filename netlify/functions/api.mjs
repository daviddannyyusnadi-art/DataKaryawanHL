import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json" } });
const SEC = () => process.env.TOKEN_SECRET || process.env.HRD_PASSWORD || "";
const sign = p => crypto.createHmac("sha256", SEC()).update(p).digest("hex");
const sha = s => crypto.createHash("sha256").update(String(s)).digest();
const mk = () => { const e = Date.now() + 12 * 3600e3; return `${e}.${sign(String(e))}`; };
const authed = req => {
  const t = (req.headers.get("authorization") || "").replace("Bearer ", "");
  const [e, s] = t.split(".");
  if (!e || !s || !/^\d+$/.test(e) || Date.now() > +e) return false;
  const a = Buffer.from(sign(e)), b = Buffer.from(s);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const KEYS = ["fKtp", "fKk", "fDiri", "fTab", "fIjz", "fCv", "fLam", "fSim"];
const NIK = "NIK (KTP)", NAMA = "Nama Lengkap Sesuai KTP";
const M = {email:"Email Address",nama:NAMA,tmpLahir:"Tempat Lahir",tglLahir:"Tanggal Lahir",kawin:"Status Perkawinan",jk:"Jenis Kelamin",agama:"Agama",dept:"Departemen (Divisi)",dom_alamat:"Alamat Domisili",dom_rt:"RT (Domisili)",dom_rw:"RW (Domisili)",dom_kel:"Kelurahan (Domisili)",dom_kec:"Kecamatan (Domisili)",dom_kota:"Kota (Domisili)",dom_prov:"Provinsi (Domisili)",nik:NIK,kk:"Nomor KK",ktp_alamat:"Alamat Lengkap Sesuai KTP",ktp_rt:"RT (KTP)",ktp_rw:"RW (KTP)",ktp_kel:"Kelurahan (KTP)",ktp_kec:"Kecamatan (KTP)",ktp_kota:"Kota (KTP)",ktp_prov:"Provinsi (KTP)",ktp_pos:"Kode Pos",hp:"Nomor HP (WA)",hp2:"Nomor HP 2",hpDar:"Nomor HP Darurat",namaDar:"Nama Kontak Darurat",hubDar:"Hubungan Kontak Darurat",ibu:"Nama Ibu Kandung",ayah:"Nama Ayah Kandung",tinggal:"Status Tempat Tinggal",bpjsKes:"Nomor BPJS Kesehatan",bpjsTk:"Nomor BPJS Ketenagakerjaan",didik:"Pendidikan Terakhir",sekolah:"Nama Sekolah/Universitas",jurusan:"Jurusan / Bidang Keahlian",lulus:"Tahun Kelulusan",npwp:"Nomor NPWP",rek:"Nomor Rekening",bank:"Nama Bank"};
const clean = v => String(v ?? "").trim().slice(0, 500);
const isNik = v => /^\d{16}$/.test(String(v || ""));
const DEPT = ["Production", "ME", "Logistic", "HR", "Warehouse"];
const LEN = ["Departemen (Divisi)", "Posisi / Jabatan", "Alamat Domisili", "RT (Domisili)", "RW (Domisili)", "Kelurahan (Domisili)", "Kecamatan (Domisili)", "Kota (Domisili)", "Provinsi (Domisili)", "Kode Pos", "Nomor KK", "Nama Ibu Kandung", "Nama Ayah Kandung", "Status Tempat Tinggal", "Nomor HP (WA)", "Nomor HP Darurat", "Nama Kontak Darurat", "Hubungan Kontak Darurat", "Pendidikan Terakhir", "Nama Sekolah/Universitas", "Jurusan / Bidang Keahlian", "Tahun Kelulusan", "Nama Bank", "Nomor Rekening"];
const EDIT = [...LEN, "Nomor HP 2", "Nomor BPJS Kesehatan", "Nomor BPJS Ketenagakerjaan", "Nomor NPWP"];
const DOCS = ["fKk", "fDiri", "fTab"];
const kelengkapan = r => {
  const kurang = LEN.filter(k => !(k === "Posisi / Jabatan" ? (r[k] || r["Posisi / Jabatan 1"]) : r[k]));
  DOCS.forEach(d => { if (!(r.berkas || []).includes(d)) kurang.push(d); });
  const total = LEN.length + DOCS.length;
  return { persen: Math.round((total - kurang.length) / total * 100), kurang };
};
const toBuf = b => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);

const wib = () => { const w = new Date(Date.now() + 7 * 36e5).toISOString(); return { tanggal: w.slice(0, 10), jam: w.slice(11, 16) }; };
const hashPin = (pin, salt) => crypto.scryptSync(String(pin), salt, 32).toString("hex");
const same = (x, y) => { const a = Buffer.from(String(x)), b = Buffer.from(String(y)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const empTok = nik => { const e = Date.now() + 12 * 3600e3; return `${nik}:${e}.${sign("emp:" + nik + ":" + e)}`; };
const empAuth = req => {
  const t = (req.headers.get("authorization") || "").replace("Bearer ", "");
  const [p, s] = t.split(".");
  if (!p || !s) return null;
  const [nik, e] = p.split(":");
  if (!isNik(nik) || !/^\d+$/.test(e || "") || Date.now() > +e) return null;
  return same(sign("emp:" + nik + ":" + e), s) ? nik : null;
};
const kTok = kode => { const e = Date.now() + 12 * 3600e3; return `${kode}:${e}.${sign("kl:" + kode + ":" + e)}`; };
const kAuth = req => {
  const t = (req.headers.get("authorization") || "").replace("Bearer ", "");
  const [p, s] = t.split(".");
  if (!p || !s) return null;
  const [kode, e] = p.split(":");
  if (!/^[a-z0-9-]{2,20}$/.test(kode || "") || !/^\d+$/.test(e || "") || Date.now() > +e) return null;
  return same(sign("kl:" + kode + ":" + e), s) ? kode : null;
};
const dobOf = emp => { const m = String(emp["Tanggal Lahir"] || "").match(/^(\d{4})-(\d{2})-(\d{2})/); return m ? m[3] + m[2] + m[1] : null; };

async function inChunks(arr, n, fn) {
  const out = [];
  for (let i = 0; i < arr.length; i += n) out.push(...await Promise.all(arr.slice(i, i + n).map(fn)));
  return out;
}

export default async (req) => {
  const route = new URL(req.url).pathname.replace(/^\/api\//, "").replace(/\/$/, "");
  const kar = getStore({ name: "karyawan", consistency: "strong" });
  const ber = getStore({ name: "berkas", consistency: "strong" });
  const abs = getStore({ name: "absensi", consistency: "strong" });
  const akun = getStore({ name: "akun", consistency: "strong" });
  const selfie = getStore({ name: "selfie", consistency: "strong" });
  const setting = getStore({ name: "pengaturan", consistency: "strong" });
  const klaim = getStore({ name: "nipklaim", consistency: "strong" });
  const klien = getStore({ name: "klien", consistency: "strong" });
  const mcu = getStore({ name: "mcu", consistency: "strong" });
  const nipCfg = async () => ({ prefix: "", digits: 5, next: 1, ...((await setting.get("nip", { type: "json" })) || {}) });
  const nipCtx = async () => { const { blobs } = await klaim.list(); return { cfg: await nipCfg(), taken: new Set(blobs.map(b => b.key)) }; };
  const nipFmt = (c, n) => c.prefix + String(n).padStart(c.digits, "0");
  const alloc = ctx => { let n = ctx.cfg.next; while (ctx.taken.has(nipFmt(ctx.cfg, n))) n++; const nip = nipFmt(ctx.cfg, n); ctx.taken.add(nip); ctx.cfg.next = n + 1; return nip; };
  const bump = (ctx, nip) => { const p = ctx.cfg.prefix; if (nip.startsWith(p)) { const t = nip.slice(p.length); if (/^\d{1,9}$/.test(t) && +t >= ctx.cfg.next) ctx.cfg.next = +t + 1; } };
  try {
    if (route === "register" && req.method === "POST") {
      const b = await req.json();
      const r = {};
      for (const k in M) if (b[k] != null) r[M[k]] = clean(b[k]);
      if (b.posisi) r["Posisi / Jabatan"] = clean(Array.isArray(b.posisi) ? b.posisi[0] : b.posisi);
      if (!isNik(r[NIK]) || !r[NAMA] || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(r["Email Address"] || "")) return J({ error: "data tidak valid" }, 400);
      for (const k of ["fKtp", "fIjz"]) if (!(await ber.getMetadata(`${r[NIK]}/${k}`))) return J({ error: "Foto KTP dan ijazah wajib diunggah" }, 400);
      if (await kar.get(r[NIK])) return J({ error: "NIK sudah terdaftar" }, 409);
      const lahir = new Date(r["Tanggal Lahir"]);
      if (!isNaN(lahir)) { const n = new Date(); let a = n.getFullYear() - lahir.getFullYear(); if (n < new Date(n.getFullYear(), lahir.getMonth(), lahir.getDate())) a--; r["Usia"] = String(a); }
      r["Timestamp Registrasi"] = new Date().toISOString();
      r.berkas = (Array.isArray(b.berkas) ? b.berkas : []).map(x => String(x).split(":")[0]).filter(k => KEYS.includes(k));
      const ctx = await nipCtx(); r["NIP Pegawai"] = alloc(ctx);
      await Promise.all([kar.setJSON(r[NIK], r), klaim.set(r["NIP Pegawai"], r[NIK]), setting.setJSON("nip", ctx.cfg)]);
      return J({ ok: true, nip: r["NIP Pegawai"] });
    }
    if (route === "upload" && req.method === "POST") {
      const b = await req.json();
      const m = String(b.data || "").match(/^data:([\w\/+.-]+);base64,(.+)$/s);
      if (!isNik(b.nik) || !KEYS.includes(b.key) || !m || !(m[1].startsWith("image/") || m[1] === "application/pdf")) return J({ error: "berkas tidak valid" }, 400);
      if (await kar.get(b.nik)) return J({ error: "NIK sudah terdaftar" }, 409);
      const buf = Buffer.from(m[2], "base64");
      if (buf.length > 3.6e6) return J({ error: "terlalu besar" }, 413);
      await ber.set(`${b.nik}/${b.key}`, toBuf(buf), { metadata: { type: m[1], name: clean(b.name) } });
      return J({ ok: true });
    }
    if (route === "login" && req.method === "POST") {
      const pw = process.env.HRD_PASSWORD;
      if (!pw) return J({ error: "HRD_PASSWORD belum diatur di Netlify" }, 500);
      const b = await req.json();
      if (crypto.timingSafeEqual(sha(b.password), sha(pw))) return J({ token: mk() });
      await new Promise(r => setTimeout(r, 900));
      return J({ error: "kata sandi salah" }, 401);
    }
    if (route.startsWith("emp/")) {
      if (route === "emp/login" && req.method === "POST") {
        const b = await req.json();
        const sandi = String(b.sandi || "").replace(/\D/g, "");
        const bad = () => J({ error: "NIK atau kata sandi salah" }, 401);
        if (!isNik(b.nik)) return bad();
        const emp = await kar.get(b.nik, { type: "json" });
        const ac = (await akun.get(b.nik, { type: "json" })) || {};
        if (ac.kunci && Date.now() < ac.kunci) return J({ error: "Terlalu banyak percobaan salah. Coba lagi 15 menit lagi." }, 429);
        let ok = false;
        if (emp) ok = ac.hash ? same(hashPin(sandi, ac.salt), ac.hash) : (dobOf(emp) !== null && same(dobOf(emp), sandi));
        if (!ok) {
          if (emp) { ac.gagal = (ac.gagal || 0) + 1; if (ac.gagal >= 5) { ac.kunci = Date.now() + 15 * 60e3; ac.gagal = 0; } await akun.setJSON(b.nik, ac); }
          await new Promise(r => setTimeout(r, 700));
          return bad();
        }
        ac.gagal = 0; delete ac.kunci; await akun.setJSON(b.nik, ac);
        return J({ token: empTok(b.nik), nama: emp[NAMA], baru: !ac.hash });
      }
      const nik = empAuth(req);
      if (!nik) return J({ error: "Sesi habis. Silakan masuk lagi." }, 401);
      const emp = await kar.get(nik, { type: "json" });
      if (!emp) return J({ error: "Data karyawan tidak ditemukan." }, 404);
      const ac = (await akun.get(nik, { type: "json" })) || {};
      if (route === "emp/pin" && req.method === "POST") {
        const b = await req.json(), pin = String(b.pin || "");
        if (ac.hash) return J({ error: "PIN sudah dibuat. Hubungi HRD jika lupa PIN." }, 409);
        if (!/^\d{6}$/.test(pin)) return J({ error: "PIN harus 6 angka" }, 400);
        ac.salt = crypto.randomBytes(16).toString("hex"); ac.hash = hashPin(pin, ac.salt);
        await akun.setJSON(nik, ac);
        return J({ ok: true });
      }
      if (route === "emp/profil" && req.method === "GET") return J({ nama: emp[NAMA], data: Object.fromEntries(EDIT.map(k => [k, emp[k] ?? (k === "Posisi / Jabatan" ? emp["Posisi / Jabatan 1"] ?? "" : "")])), berkas: emp.berkas || [], ...kelengkapan(emp) });
      if (route === "emp/profil" && req.method === "POST") {
        const { data } = await req.json(), up = {};
        for (const k of EDIT) {
          if (!data || data[k] == null) continue;
          const v = clean(data[k]);
          const bad = !v ? "" : (k === "Departemen (Divisi)" && !(DEPT.includes(v) || /^Lainnya(: .+)?$/.test(v))) ? "pilih dari daftar"
            : (k === "Posisi / Jabatan" && !(v === "Daily Worker" || /^Lainnya(: .+)?$/.test(v))) ? "pilih dari daftar"
            : (k === "Nomor KK" && !/^\d{16}$/.test(v)) ? "harus 16 digit"
            : (k === "Kode Pos" && !/^\d{5}$/.test(v)) ? "harus 5 digit"
            : (k === "Tahun Kelulusan" && !/^\d{4}$/.test(v)) ? "harus 4 digit"
            : (k.startsWith("Nomor HP") && !/^(\+62|62|0)8\d{7,12}$/.test(v.replace(/[\s-]/g, ""))) ? "tidak valid, contoh 081234567890" : "";
          if (bad) return J({ error: `${k}: ${bad}` }, 400);
          up[k] = v;
        }
        const nu = { ...emp, ...up, diperbarui: new Date().toISOString() };
        await kar.setJSON(nik, nu);
        return J({ ok: true, ...kelengkapan(nu) });
      }
      if (route === "emp/berkas" && req.method === "POST") {
        const b = await req.json();
        const m = String(b.data || "").match(/^data:([\w\/+.-]+);base64,(.+)$/s);
        if (!KEYS.includes(b.key) || !m || !(m[1].startsWith("image/") || m[1] === "application/pdf")) return J({ error: "berkas tidak valid" }, 400);
        const buf = Buffer.from(m[2], "base64");
        if (buf.length > 3.6e6) return J({ error: "Ukuran berkas terlalu besar" }, 413);
        await ber.set(`${nik}/${b.key}`, toBuf(buf), { metadata: { type: m[1], name: clean(b.name) } });
        const nu = { ...emp, berkas: [...new Set([...(emp.berkas || []), b.key])], diperbarui: new Date().toISOString() };
        await kar.setJSON(nik, nu);
        return J({ ok: true, ...kelengkapan(nu) });
      }
      const { tanggal, jam } = wib();
      const key = `${tanggal}/${nik}`;
      const rec = (await abs.get(key, { type: "json" })) || { nik, nama: emp[NAMA], tanggal };
      if (route === "emp/status" && req.method === "GET") return J({ nama: emp[NAMA], perluPin: !ac.hash, tanggal, masuk: rec.masuk || "", pulang: rec.pulang || "", idAmbil: rec.idAmbil || "", idKembali: rec.idKembali || "", izin: !!rec.izin, ...kelengkapan(emp) });
      if (route === "emp/absen" && req.method === "POST") {
        if (!ac.hash) return J({ error: "Buat PIN dulu sebelum absen." }, 403);
        const b = await req.json();
        const m = String(b.foto || "").match(/^data:(image\/(?:jpeg|png|webp));base64,(.+)$/s);
        if (!["masuk", "pulang"].includes(b.aksi)) return J({ error: "Data tidak valid" }, 400);
        if (!m) return J({ error: "Foto selfie wajib diunggah" }, 400);
        const buf = Buffer.from(m[2], "base64");
        if (buf.length > 1.5e6) return J({ error: "Foto terlalu besar" }, 413);
        if (b.aksi === "masuk" && rec.masuk) return J({ ok: true, sudah: true, nama: emp[NAMA], jam: rec.masuk, aksi: "masuk" });
        if (b.aksi === "pulang" && !rec.masuk) return J({ error: "Absen masuk dulu hari ini." }, 409);
        if (b.aksi === "masuk" && !rec.idAmbil && !rec.izin) return J({ error: "Absen masuk bisa dipakai setelah mengambil ID card, atau seizin HRD." }, 403);
        const ok = b.lat !== null && b.lat !== "" && b.lng !== null && b.lng !== "" && Number.isFinite(+b.lat) && Number.isFinite(+b.lng) && Math.abs(+b.lat) <= 90 && Math.abs(+b.lng) <= 180;
        const lok = ok ? `${(+b.lat).toFixed(5)},${(+b.lng).toFixed(5)}` : "";
        await selfie.set(`${tanggal}/${nik}/${b.aksi}`, toBuf(buf), { metadata: { type: m[1] } });
        const A = b.aksi === "masuk" ? "Masuk" : "Pulang";
        rec[b.aksi] = jam; rec["lok" + A] = lok; rec["foto" + A] = true;
        await abs.setJSON(key, rec);
        return J({ ok: true, nama: emp[NAMA], jam, aksi: b.aksi, tanggal });
      }
      if (route === "emp/idcard" && req.method === "POST") {
        if (!ac.hash) return J({ error: "Buat PIN dulu." }, 403);
        const b = await req.json();
        const m = String(b.foto || "").match(/^data:(image\/(?:jpeg|png|webp));base64,(.+)$/s);
        if (!["idambil", "idkembali"].includes(b.aksi)) return J({ error: "Data tidak valid" }, 400);
        if (!m) return J({ error: "Foto ID card wajib diunggah" }, 400);
        const buf = Buffer.from(m[2], "base64");
        if (buf.length > 1.5e6) return J({ error: "Foto terlalu besar" }, 413);
        if (b.aksi === "idambil" && rec.idAmbil) return J({ ok: true, sudah: true, nama: emp[NAMA], jam: rec.idAmbil, aksi: b.aksi });
        await selfie.set(`${tanggal}/${nik}/${b.aksi}`, toBuf(buf), { metadata: { type: m[1] } });
        if (b.aksi === "idambil") { rec.idAmbil = jam; rec.fotoIdambil = true; } else { rec.idKembali = jam; rec.fotoIdkembali = true; }
        await abs.setJSON(key, rec);
        return J({ ok: true, nama: emp[NAMA], jam, aksi: b.aksi, tanggal });
      }
    }
    if (route.startsWith("kl/")) {
      if (route === "kl/login" && req.method === "POST") {
        const b = await req.json(), kode = String(b.kode || "").trim().toLowerCase();
        const k = /^[a-z0-9-]{2,20}$/.test(kode) ? await klien.get(kode, { type: "json" }) : null;
        if (k && k.kunci && Date.now() < k.kunci) return J({ error: "Terlalu banyak percobaan salah. Coba lagi 15 menit lagi." }, 429);
        if (!(k && same(hashPin(String(b.sandi || ""), k.salt), k.hash))) {
          if (k) { k.gagal = (k.gagal || 0) + 1; if (k.gagal >= 5) { k.kunci = Date.now() + 15 * 60e3; k.gagal = 0; } await klien.setJSON(kode, k); }
          await new Promise(r => setTimeout(r, 700));
          return J({ error: "Kode klien atau kata sandi salah" }, 401);
        }
        k.gagal = 0; delete k.kunci; await klien.setJSON(kode, k);
        return J({ token: kTok(kode), nama: k.nama });
      }
      const kode = kAuth(req);
      if (!kode) return J({ error: "Sesi habis. Silakan masuk lagi." }, 401);
      const k = await klien.get(kode, { type: "json" });
      if (!k) return J({ error: "Akun klien tidak ditemukan." }, 404);
      if (route === "kl/data" && req.method === "GET") {
        const { blobs } = await mcu.list({ prefix: kode + "/" });
        const rows = await inChunks(blobs, 40, x => mcu.get(x.key, { type: "json" }));
        return J({ nama: k.nama, rows: rows.filter(Boolean) });
      }
      if (route === "kl/simpan" && req.method === "POST") {
        const { rows } = await req.json();
        if (!Array.isArray(rows) || rows.length > 100) return J({ error: "maks 100 baris per permintaan" }, 400);
        const ditolak = [], ok = [];
        for (const r of rows) {
          const nik = String(r?.nik || "").replace(/\D/g, ""), nama = clean(r?.nama), s = String(r?.status || "");
          const st = /^sudah/i.test(s) ? "Sudah" : /^belum/i.test(s) ? "Belum" : "", tg = String(r?.tanggal || "").trim();
          const tgOk = /^\d{4}-\d{2}-\d{2}$/.test(tg) && !isNaN(new Date(tg));
          const al = !isNik(nik) ? "NIK harus 16 digit" : !nama ? "nama kosong" : !st ? "status MCU harus Sudah atau Belum" : tg && !tgOk ? "tanggal MCU tidak valid" : st === "Sudah" && !tg ? "tanggal MCU wajib jika sudah MCU" : "";
          if (al) { ditolak.push({ nik: nik || "?", alasan: al }); continue; }
          ok.push([nik, { nik, nama, status: st, tanggal: tg, keterangan: clean(r.keterangan).slice(0, 300), klien: kode, klienNama: k.nama, diperbarui: new Date().toISOString() }]);
        }
        await inChunks(ok, 20, ([n, v]) => mcu.setJSON(`${kode}/${n}`, v));
        return J({ ok: true, saved: ok.length, ditolak });
      }
      if (route === "kl/hapus" && req.method === "POST") {
        const { niks } = await req.json();
        if (!Array.isArray(niks) || niks.length > 50) return J({ error: "maks 50 per permintaan" }, 400);
        await inChunks(niks.filter(isNik), 10, n => mcu.delete(`${kode}/${n}`));
        return J({ ok: true });
      }
    }
    if (!authed(req)) return J({ error: "unauthorized" }, 401);
    if (route === "karyawan" && req.method === "GET") {
      const { blobs } = await kar.list();
      const rows = await inChunks(blobs, 40, x => kar.get(x.key, { type: "json" }));
      return J(rows.filter(Boolean).map(r => ({ ...r, lengkap: kelengkapan(r).persen })));
    }
    if (route === "import" && req.method === "POST") {
      const { rows } = await req.json();
      if (!Array.isArray(rows) || rows.length > 100) return J({ error: "maks 100 baris per permintaan" }, 400);
      const good = rows.filter(r => r && isNik(r[NIK]) && r[NAMA]);
      const ctx = await nipCtx(), ditolak = [], out = [], claims = [], releases = [], seen = {};
      const olds = await inChunks(good, 20, r => kar.get(r[NIK], { type: "json" }));
      const owners = await inChunks(good, 20, async r => { const n = clean(r["NIP Pegawai"]); return /^[\w.-]{1,30}$/.test(n) ? await klaim.get(n) : null; });
      good.forEach((r, i) => {
        const old = olds[i] || {}, row = {}, nik = r[NIK];
        for (const k in r) if (k !== "berkas") row[k] = clean(r[k]);
        let nip = row["NIP Pegawai"] || "";
        if (nip) {
          if (!/^[\w.-]{1,30}$/.test(nip)) return ditolak.push({ nik, alasan: "format NIP tidak valid" });
          if ((owners[i] && owners[i] !== nik) || (seen[nip] && seen[nip] !== nik)) return ditolak.push({ nik, alasan: `NIP ${nip} sudah dipakai karyawan lain` });
          seen[nip] = nik; ctx.taken.add(nip); bump(ctx, nip);
        } else nip = old["NIP Pegawai"] || alloc(ctx);
        row["NIP Pegawai"] = nip;
        if (nip !== old["NIP Pegawai"]) { claims.push([nip, nik]); if (old["NIP Pegawai"]) releases.push(old["NIP Pegawai"]); }
        out.push([nik, { ...old, ...row, diperbarui: new Date().toISOString() }]);
      });
      await inChunks(out, 20, ([n, v]) => kar.setJSON(n, v));
      await inChunks(claims, 20, ([n, k]) => klaim.set(n, k));
      await inChunks(releases, 20, n => klaim.delete(n));
      await setting.setJSON("nip", ctx.cfg);
      return J({ ok: true, saved: out.length, ditolak });
    }
    if (route === "absensi" && req.method === "GET") {
      const bulan = new URL(req.url).searchParams.get("bulan") || "";
      if (!/^\d{4}-\d{2}$/.test(bulan)) return J({ error: "bulan tidak valid" }, 400);
      const { blobs } = await abs.list({ prefix: bulan + "-" });
      const rows = await inChunks(blobs, 40, x => abs.get(x.key, { type: "json" }));
      return J(rows.filter(Boolean));
    }
    if (route === "hapus" && req.method === "POST") {
      const { niks } = await req.json();
      if (!Array.isArray(niks) || niks.length > 50) return J({ error: "maks 50 per permintaan" }, 400);
      const ids = niks.filter(isNik);
      await inChunks(ids, 10, async n => {
        await kar.delete(n);
        await akun.delete(n);
        const { blobs } = await ber.list({ prefix: n + "/" });
        await Promise.all(blobs.map(x => ber.delete(x.key)));
      });
      return J({ ok: true, deleted: ids.length });
    }
    if (route === "selfie" && req.method === "GET") {
      const u = new URL(req.url), t = u.searchParams.get("tanggal") || "", n = u.searchParams.get("nik"), ak = u.searchParams.get("aksi");
      if (!/^\d{4}-\d{2}-\d{2}$/.test(t) || !isNik(n) || !["masuk", "pulang", "idambil", "idkembali"].includes(ak)) return J({ error: "bad request" }, 400);
      const f = await selfie.getWithMetadata(`${t}/${n}/${ak}`, { type: "arrayBuffer" });
      if (!f) return J({ error: "tidak ada" }, 404);
      return new Response(f.data, { headers: { "Content-Type": f.metadata?.type || "image/jpeg" } });
    }
    if (route === "resetpin" && req.method === "POST") {
      const { niks } = await req.json();
      if (!Array.isArray(niks) || niks.length > 50) return J({ error: "maks 50 per permintaan" }, 400);
      const ids = niks.filter(isNik);
      await inChunks(ids, 10, n => akun.delete(n));
      return J({ ok: true, reset: ids.length });
    }
    if (route === "nip" && req.method === "GET") return J(await nipCfg());
    if (route === "nip" && req.method === "POST") {
      const b = await req.json(), prefix = String(b.prefix ?? "").trim(), digits = Math.floor(+b.digits), next = Math.floor(+b.next);
      if (!/^[A-Za-z0-9._-]{0,10}$/.test(prefix)) return J({ error: "Awalan maks 10 karakter: huruf, angka, titik, minus" }, 400);
      if (!(digits >= 1 && digits <= 10) || !(next >= 1 && next < 1e9)) return J({ error: "Digit 1-10 dan nomor berikutnya harus angka positif" }, 400);
      await setting.setJSON("nip", { prefix, digits, next });
      return J({ ok: true });
    }
    if (route === "nip/isi" && req.method === "POST") {
      const ctx = await nipCtx();
      const { blobs } = await kar.list();
      const all = (await inChunks(blobs, 40, x => kar.get(x.key, { type: "json" }))).filter(Boolean);
      const need = all.filter(r => !r["NIP Pegawai"]).sort((x, y) => String(x["Timestamp Registrasi"] || "").localeCompare(String(y["Timestamp Registrasi"] || "")) || String(x[NAMA]).localeCompare(String(y[NAMA])));
      const batch = need.slice(0, 300), claims = [];
      batch.forEach(r => { r["NIP Pegawai"] = alloc(ctx); claims.push([r["NIP Pegawai"], r[NIK]]); });
      await inChunks(batch, 20, r => kar.setJSON(r[NIK], r));
      await inChunks(claims, 20, ([n, k]) => klaim.set(n, k));
      await setting.setJSON("nip", ctx.cfg);
      return J({ ok: true, diisi: batch.length, sisa: need.length - batch.length });
    }
    if (route === "mcu" && req.method === "GET") {
      const { blobs } = await mcu.list();
      return J((await inChunks(blobs, 40, x => mcu.get(x.key, { type: "json" }))).filter(Boolean));
    }
    if (route === "klien" && req.method === "GET") {
      const { blobs } = await klien.list();
      const rows = (await inChunks(blobs, 40, x => klien.get(x.key, { type: "json" }))).filter(Boolean);
      return J(rows.map(k => ({ kode: k.kode, nama: k.nama })));
    }
    if (route === "klien" && req.method === "POST") {
      const b = await req.json(), kode = String(b.kode || "").trim().toLowerCase(), nama = clean(b.nama), sandi = String(b.sandi || "");
      if (!/^[a-z0-9-]{2,20}$/.test(kode) || !nama) return J({ error: "Kode (huruf kecil, angka, minus; 2-20 karakter) dan nama wajib diisi" }, 400);
      const old = await klien.get(kode, { type: "json" });
      if ((!old || sandi) && sandi.length < 8) return J({ error: "Kata sandi minimal 8 karakter" }, 400);
      const rec = { ...(old || {}), kode, nama };
      if (sandi) { rec.salt = crypto.randomBytes(16).toString("hex"); rec.hash = hashPin(sandi, rec.salt); rec.gagal = 0; delete rec.kunci; }
      await klien.setJSON(kode, rec);
      return J({ ok: true, baru: !old });
    }
    if (route === "klien/hapus" && req.method === "POST") {
      const b = await req.json(), kode = String(b.kode || "");
      if (!/^[a-z0-9-]{2,20}$/.test(kode)) return J({ error: "kode tidak valid" }, 400);
      await klien.delete(kode);
      return J({ ok: true });
    }
    if (route === "izin" && req.method === "POST") {
      const b = await req.json();
      if (!isNik(b.nik) || !/^\d{4}-\d{2}-\d{2}$/.test(b.tanggal || "")) return J({ error: "bad request" }, 400);
      const emp = await kar.get(b.nik, { type: "json" });
      if (!emp) return J({ error: "karyawan tidak ditemukan" }, 404);
      const key = `${b.tanggal}/${b.nik}`;
      const rec = (await abs.get(key, { type: "json" })) || { nik: b.nik, nama: emp[NAMA], tanggal: b.tanggal };
      rec.izin = !!b.izin;
      await abs.setJSON(key, rec);
      return J({ ok: true });
    }
    if (route === "berkas" && req.method === "GET") {
      const u = new URL(req.url), nik = u.searchParams.get("nik"), key = u.searchParams.get("key");
      if (!isNik(nik) || !KEYS.includes(key)) return J({ error: "bad request" }, 400);
      const f = await ber.getWithMetadata(`${nik}/${key}`, { type: "arrayBuffer" });
      if (!f) return J({ error: "tidak ada" }, 404);
      return new Response(f.data, { headers: { "Content-Type": f.metadata?.type || "application/octet-stream" } });
    }
  } catch (e) {
    console.error(e);
    return J({ error: "server error" }, 500);
  }
  return J({ error: "not found" }, 404);
};
export const config = { path: "/api/*" };
