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
  try {
    if (route === "register" && req.method === "POST") {
      const b = await req.json();
      const r = {};
      for (const k in M) if (b[k] != null) r[M[k]] = clean(b[k]);
      (Array.isArray(b.posisi) ? b.posisi : []).slice(0, 7).forEach((p, i) => r[`Posisi / Jabatan ${i + 1}`] = clean(p));
      if (!isNik(r[NIK]) || !r[NAMA]) return J({ error: "data tidak valid" }, 400);
      if (await kar.get(r[NIK])) return J({ error: "NIK sudah terdaftar" }, 409);
      const lahir = new Date(r["Tanggal Lahir"]);
      if (!isNaN(lahir)) { const n = new Date(); let a = n.getFullYear() - lahir.getFullYear(); if (n < new Date(n.getFullYear(), lahir.getMonth(), lahir.getDate())) a--; r["Usia"] = String(a); }
      r["Timestamp Registrasi"] = new Date().toISOString();
      r.berkas = (Array.isArray(b.berkas) ? b.berkas : []).map(x => String(x).split(":")[0]).filter(k => KEYS.includes(k));
      await kar.setJSON(r[NIK], r);
      return J({ ok: true });
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
      const { tanggal, jam } = wib();
      const key = `${tanggal}/${nik}`;
      const rec = (await abs.get(key, { type: "json" })) || { nik, nama: emp[NAMA], tanggal };
      if (route === "emp/status" && req.method === "GET") return J({ nama: emp[NAMA], perluPin: !ac.hash, tanggal, masuk: rec.masuk || "", pulang: rec.pulang || "" });
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
        const ok = b.lat !== null && b.lat !== "" && b.lng !== null && b.lng !== "" && Number.isFinite(+b.lat) && Number.isFinite(+b.lng) && Math.abs(+b.lat) <= 90 && Math.abs(+b.lng) <= 180;
        const lok = ok ? `${(+b.lat).toFixed(5)},${(+b.lng).toFixed(5)}` : "";
        await selfie.set(`${tanggal}/${nik}/${b.aksi}`, toBuf(buf), { metadata: { type: m[1] } });
        const A = b.aksi === "masuk" ? "Masuk" : "Pulang";
        rec[b.aksi] = jam; rec["lok" + A] = lok; rec["foto" + A] = true;
        await abs.setJSON(key, rec);
        return J({ ok: true, nama: emp[NAMA], jam, aksi: b.aksi, tanggal });
      }
    }
    if (!authed(req)) return J({ error: "unauthorized" }, 401);
    if (route === "karyawan" && req.method === "GET") {
      const { blobs } = await kar.list();
      const rows = await inChunks(blobs, 40, x => kar.get(x.key, { type: "json" }));
      return J(rows.filter(Boolean));
    }
    if (route === "import" && req.method === "POST") {
      const { rows } = await req.json();
      if (!Array.isArray(rows) || rows.length > 200) return J({ error: "maks 200 baris per permintaan" }, 400);
      const good = rows.filter(r => r && isNik(r[NIK]) && r[NAMA]);
      await inChunks(good, 20, async r => {
        const old = (await kar.get(r[NIK], { type: "json" })) || {};
        const row = {};
        for (const k in r) if (k !== "berkas") row[k] = clean(r[k]);
        await kar.setJSON(r[NIK], { ...old, ...row, diperbarui: new Date().toISOString() });
      });
      return J({ ok: true, saved: good.length });
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
      if (!/^\d{4}-\d{2}-\d{2}$/.test(t) || !isNik(n) || !["masuk", "pulang"].includes(ak)) return J({ error: "bad request" }, 400);
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
