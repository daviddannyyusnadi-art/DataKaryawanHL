// Cloudflare Worker: API absensi/registrasi karyawan (D1 saja, tanpa R2)
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

const dobOf = emp => { const m = String(emp["Tanggal Lahir"] || "").match(/^(\d{4})-(\d{2})-(\d{2})/); return m ? m[3] + m[2] + m[1] : null; };

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json" } });
const RAW = s => new Response(s, { headers: { "Content-Type": "application/json" } });
const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const hmac = async (secret, msg) => { const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); return hex(await crypto.subtle.sign("HMAC", k, enc.encode(msg))); };
const pbk = async (pw, salt) => { const k = await crypto.subtle.importKey("raw", enc.encode(String(pw)), "PBKDF2", false, ["deriveBits"]); return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 10000 }, k, 256)); };
const same = (a, b) => { a = String(a); b = String(b); if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const rnd = () => hex(crypto.getRandomValues(new Uint8Array(16)));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const wib = () => { const w = new Date(Date.now() + 7 * 36e5).toISOString(); return { tanggal: w.slice(0, 10), jam: w.slice(11, 16) }; };
const secret = env => env.TOKEN_SECRET || env.HRD_PASSWORD || "";
const bearer = req => (req.headers.get("authorization") || "").replace("Bearer ", "");
const scopedTok = async (env, pre, id) => { const e = Date.now() + 12 * 3600e3; return `${id}:${e}.` + await hmac(secret(env), `${pre}:${id}:${e}`); };
const scopedAuth = async (req, env, pre, re) => {
  const [p, s] = bearer(req).split("."); const [id, e] = (p || "").split(":");
  if (!re.test(id || "") || !/^\d+$/.test(e || "") || !s || Date.now() > +e) return null;
  return same(await hmac(secret(env), `${pre}:${id}:${e}`), s) ? id : null;
};
const hrTok = async env => { const e = Date.now() + 12 * 3600e3; return `${e}.` + await hmac(secret(env), String(e)); };
const hrAuth = async (req, env) => { const [e, s] = bearer(req).split("."); if (!/^\d+$/.test(e || "") || !s || Date.now() > +e) return false; return same(await hmac(secret(env), e), s); };

// ---------- database ----------
let ready;
const init = env => ready ??= env.DB.batch([
  "CREATE TABLE IF NOT EXISTS karyawan(nik TEXT PRIMARY KEY, nip TEXT UNIQUE, data TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS akun(nik TEXT PRIMARY KEY, v TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS absensi(tanggal TEXT, nik TEXT, v TEXT NOT NULL, PRIMARY KEY(tanggal, nik))",
  "CREATE TABLE IF NOT EXISTS klien(kode TEXT PRIMARY KEY, v TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS mcu(kode TEXT, nik TEXT, v TEXT NOT NULL, PRIMARY KEY(kode, nik))",
  "CREATE TABLE IF NOT EXISTS setting(k TEXT PRIMARY KEY, v TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS berkas(k TEXT NOT NULL, i INTEGER NOT NULL, d TEXT NOT NULL, PRIMARY KEY(k, i))"
].map(s => env.DB.prepare(s))).catch(e => { ready = null; throw e; });
const one = async (env, sql, ...p) => { const r = await env.DB.prepare(sql).bind(...p).first(); return r ? JSON.parse(r.v ?? r.data) : null; };
const all = async (env, sql, ...p) => (await env.DB.prepare(sql).bind(...p).all()).results;
const joinJ = rows => "[" + rows.map(r => r.v ?? r.data).join(",") + "]";
const getKar = (env, nik) => one(env, "SELECT data FROM karyawan WHERE nik=?", nik);
const karStmt = (env, o) => { o.lengkap = kelengkapan(o).persen; return env.DB.prepare("INSERT INTO karyawan(nik,nip,data) VALUES(?,?,?) ON CONFLICT(nik) DO UPDATE SET nip=excluded.nip, data=excluded.data").bind(o[NIK], o["NIP Pegawai"] || null, JSON.stringify(o)); };
const getAk = (env, nik) => one(env, "SELECT v FROM akun WHERE nik=?", nik).then(x => x || {});
const setAk = (env, nik, v) => env.DB.prepare("INSERT INTO akun(nik,v) VALUES(?,?) ON CONFLICT(nik) DO UPDATE SET v=excluded.v").bind(nik, JSON.stringify(v)).run();
const getAbs = (env, t, n) => one(env, "SELECT v FROM absensi WHERE tanggal=? AND nik=?", t, n);
const setAbs = (env, t, n, v) => env.DB.prepare("INSERT INTO absensi(tanggal,nik,v) VALUES(?,?,?) ON CONFLICT(tanggal,nik) DO UPDATE SET v=excluded.v").bind(t, n, JSON.stringify(v)).run();
const getKl = (env, k) => one(env, "SELECT v FROM klien WHERE kode=?", k);
const setKl = (env, k, v) => env.DB.prepare("INSERT INTO klien(kode,v) VALUES(?,?) ON CONFLICT(kode) DO UPDATE SET v=excluded.v").bind(k, JSON.stringify(v)).run();
const getCfg = async env => ({ prefix: "", digits: 5, next: 1, ...((await one(env, "SELECT v FROM setting WHERE k=?", "nip")) || {}) });
const setCfg = (env, c) => env.DB.prepare("INSERT INTO setting(k,v) VALUES('nip',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify(c)).run();
const nipFmt = (c, n) => c.prefix + String(n).padStart(c.digits, "0");
const alloc = (cfg, owner) => { let n = cfg.next; while (owner.has(nipFmt(cfg, n))) n++; cfg.next = n + 1; return nipFmt(cfg, n); };
const bump = (cfg, nip) => { if (nip.startsWith(cfg.prefix)) { const t = nip.slice(cfg.prefix.length); if (/^\d{1,9}$/.test(t) && +t >= cfg.next) cfg.next = +t + 1; } };
const TIPE = /^data:(image\/(?:jpeg|png|webp)|application\/pdf);base64,/;
const putFile = (env, k, url) => {
  const st = [env.DB.prepare("DELETE FROM berkas WHERE k=?").bind(k)];
  for (let i = 0, n = 0; i < url.length; i += 900000, n++) st.push(env.DB.prepare("INSERT INTO berkas(k,i,d) VALUES(?,?,?)").bind(k, n, url.slice(i, i + 900000)));
  return env.DB.batch(st);
};
const hasFile = async (env, k) => !!(await env.DB.prepare("SELECT 1 AS x FROM berkas WHERE k=? AND i=0").bind(k).first());
const getFile = async (env, k) => { const rs = await all(env, "SELECT d FROM berkas WHERE k=? ORDER BY i", k); return rs.length ? rs.map(r => r.d).join("") : null; };
const okFile = (url, max) => typeof url === "string" && url.length <= max * 1.37 && TIPE.test(url.slice(0, 60));
const chunk = (a, n) => { const o = []; for (let i = 0; i < a.length; i += n) o.push(a.slice(i, i + n)); return o; };

export default {
  async fetch(req, env) {
    const u = new URL(req.url);
    if (!u.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    try { if (!secret(env)) return J({ error: "HRD_PASSWORD belum diatur di Cloudflare" }, 500); await init(env); return await api(req, env, u); }
    catch (e) { console.error(e); return J({ error: "server error" }, 500); }
  }
};

async function api(req, env, u) {
  const route = u.pathname.replace(/^\/api\//, "").replace(/\/$/, ""), post = req.method === "POST", get = req.method === "GET", q = u.searchParams;

  if (route === "register" && post) {
    const b = await req.json(), r = {};
    for (const k in M) if (b[k] != null) r[M[k]] = clean(b[k]);
    if (b.posisi) r["Posisi / Jabatan"] = clean(Array.isArray(b.posisi) ? b.posisi[0] : b.posisi);
    if (!isNik(r[NIK]) || !r[NAMA] || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(r["Email Address"] || "")) return J({ error: "data tidak valid" }, 400);
    if (await getKar(env, r[NIK])) return J({ error: "NIK sudah terdaftar" }, 409);
    for (const k of ["fKtp", "fIjz"]) if (!(await hasFile(env, `b/${r[NIK]}/${k}`))) return J({ error: "Foto KTP dan ijazah wajib diunggah" }, 400);
    const lahir = new Date(r["Tanggal Lahir"]);
    if (!isNaN(lahir)) { const n = new Date(); let a = n.getFullYear() - lahir.getFullYear(); if (n < new Date(n.getFullYear(), lahir.getMonth(), lahir.getDate())) a--; r["Usia"] = String(a); }
    r["Timestamp Registrasi"] = new Date().toISOString();
    r.berkas = (Array.isArray(b.berkas) ? b.berkas : []).map(x => String(x).split(":")[0]).filter(k => KEYS.includes(k));
    r.lengkap = kelengkapan(r).persen;
    const cfg = await getCfg(env); let n = cfg.next, ok = false;
    for (let i = 0; i < 30 && !ok; i++) {
      r["NIP Pegawai"] = nipFmt(cfg, n);
      try { await env.DB.prepare("INSERT INTO karyawan(nik,nip,data) VALUES(?,?,?)").bind(r[NIK], r["NIP Pegawai"], JSON.stringify(r)).run(); ok = true; }
      catch (e) { const m = String(e.message || e); if (m.includes("karyawan.nik")) return J({ error: "NIK sudah terdaftar" }, 409); if (!/UNIQUE/i.test(m)) throw e; n++; }
    }
    if (!ok) return J({ error: "gagal membuat NIP" }, 500);
    if (n + 1 > cfg.next) { cfg.next = n + 1; await setCfg(env, cfg); }
    return J({ ok: true, nip: r["NIP Pegawai"] });
  }
  if (route === "upload" && post) {
    const b = await req.json();
    if (!isNik(b.nik) || !KEYS.includes(b.key) || !okFile(b.data, 3.6e6)) return J({ error: "berkas tidak valid" }, 400);
    if (await getKar(env, b.nik)) return J({ error: "NIK sudah terdaftar" }, 409);
    await putFile(env, `b/${b.nik}/${b.key}`, b.data);
    return J({ ok: true });
  }
  if (route === "login" && post) {
    const b = await req.json();
    if (same(await hmac("c", String(b.password ?? "")), await hmac("c", env.HRD_PASSWORD || "\u0000"))) return J({ token: await hrTok(env) });
    await sleep(900); return J({ error: "kata sandi salah" }, 401);
  }

  if (route.startsWith("emp/")) {
    if (route === "emp/login" && post) {
      const b = await req.json(), sandi = String(b.sandi || "").replace(/\D/g, "");
      const bad = async () => { await sleep(700); return J({ error: "NIK atau kata sandi salah" }, 401); };
      if (!isNik(b.nik)) return bad();
      const emp = await getKar(env, b.nik), ac = await getAk(env, b.nik);
      if (ac.kunci && Date.now() < ac.kunci) return J({ error: "Terlalu banyak percobaan salah. Coba lagi 15 menit lagi." }, 429);
      let ok = false;
      if (emp) ok = ac.hash ? same(await pbk(sandi, ac.salt), ac.hash) : (dobOf(emp) !== null && same(dobOf(emp), sandi));
      if (!ok) { if (emp) { ac.gagal = (ac.gagal || 0) + 1; if (ac.gagal >= 5) { ac.kunci = Date.now() + 15 * 60e3; ac.gagal = 0; } await setAk(env, b.nik, ac); } return bad(); }
      ac.gagal = 0; delete ac.kunci; await setAk(env, b.nik, ac);
      return J({ token: await scopedTok(env, "emp", b.nik), nama: emp[NAMA], baru: !ac.hash });
    }
    const nik = await scopedAuth(req, env, "emp", /^\d{16}$/);
    if (!nik) return J({ error: "Sesi habis. Silakan masuk lagi." }, 401);
    const emp = await getKar(env, nik);
    if (!emp) return J({ error: "Data karyawan tidak ditemukan." }, 404);
    const ac = await getAk(env, nik);
    if (route === "emp/pin" && post) {
      const pin = String((await req.json()).pin || "");
      if (ac.hash) return J({ error: "PIN sudah dibuat. Hubungi HRD jika lupa PIN." }, 409);
      if (!/^\d{6}$/.test(pin)) return J({ error: "PIN harus 6 angka" }, 400);
      ac.salt = rnd(); ac.hash = await pbk(pin, ac.salt); await setAk(env, nik, ac);
      return J({ ok: true });
    }
    if (route === "emp/profil" && get) return J({ nama: emp[NAMA], data: Object.fromEntries(EDIT.map(k => [k, emp[k] ?? (k === "Posisi / Jabatan" ? emp["Posisi / Jabatan 1"] ?? "" : "")])), berkas: emp.berkas || [], ...kelengkapan(emp) });
    if (route === "emp/profil" && post) {
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
      await karStmt(env, nu).run();
      return J({ ok: true, ...kelengkapan(nu) });
    }
    if (route === "emp/berkas" && post) {
      const b = await req.json();
      if (!KEYS.includes(b.key) || !okFile(b.data, 3.6e6)) return J({ error: "berkas tidak valid" }, 400);
      await putFile(env, `b/${nik}/${b.key}`, b.data);
      const nu = { ...emp, berkas: [...new Set([...(emp.berkas || []), b.key])], diperbarui: new Date().toISOString() };
      await karStmt(env, nu).run();
      return J({ ok: true, ...kelengkapan(nu) });
    }
    const { tanggal, jam } = wib();
    const rec = (await getAbs(env, tanggal, nik)) || { nik, nama: emp[NAMA], tanggal };
    if (route === "emp/status" && get) return J({ nama: emp[NAMA], perluPin: !ac.hash, tanggal, masuk: rec.masuk || "", pulang: rec.pulang || "", idAmbil: rec.idAmbil || "", idKembali: rec.idKembali || "", izin: !!rec.izin, ...kelengkapan(emp) });
    const lokOf = b => { const ok = b.lat !== null && b.lat !== "" && b.lng !== null && b.lng !== "" && Number.isFinite(+b.lat) && Number.isFinite(+b.lng) && Math.abs(+b.lat) <= 90 && Math.abs(+b.lng) <= 180; return ok ? `${(+b.lat).toFixed(5)},${(+b.lng).toFixed(5)}` : ""; };
    if (route === "emp/absen" && post) {
      if (!ac.hash) return J({ error: "Buat PIN dulu sebelum absen." }, 403);
      const b = await req.json();
      if (!["masuk", "pulang"].includes(b.aksi)) return J({ error: "Data tidak valid" }, 400);
      if (!okFile(b.foto, 1.5e6) || !b.foto.startsWith("data:image/")) return J({ error: "Foto selfie wajib diunggah" }, 400);
      if (b.aksi === "masuk" && rec.masuk) return J({ ok: true, sudah: true, nama: emp[NAMA], jam: rec.masuk, aksi: "masuk" });
      if (b.aksi === "pulang" && !rec.masuk) return J({ error: "Absen masuk dulu hari ini." }, 409);
      if (b.aksi === "masuk" && !rec.idAmbil && !rec.izin) return J({ error: "Absen masuk bisa dipakai setelah mengambil ID card, atau seizin HRD." }, 403);
      await putFile(env, `s/${tanggal}/${nik}/${b.aksi}`, b.foto);
      const A = b.aksi === "masuk" ? "Masuk" : "Pulang";
      rec[b.aksi] = jam; rec["lok" + A] = lokOf(b); rec["foto" + A] = true;
      await setAbs(env, tanggal, nik, rec);
      return J({ ok: true, nama: emp[NAMA], jam, aksi: b.aksi, tanggal });
    }
    if (route === "emp/idcard" && post) {
      if (!ac.hash) return J({ error: "Buat PIN dulu." }, 403);
      const b = await req.json();
      if (!["idambil", "idkembali"].includes(b.aksi)) return J({ error: "Data tidak valid" }, 400);
      if (!okFile(b.foto, 1.5e6) || !b.foto.startsWith("data:image/")) return J({ error: "Foto ID card wajib diunggah" }, 400);
      if (b.aksi === "idambil" && rec.idAmbil) return J({ ok: true, sudah: true, nama: emp[NAMA], jam: rec.idAmbil, aksi: b.aksi });
      await putFile(env, `s/${tanggal}/${nik}/${b.aksi}`, b.foto);
      if (b.aksi === "idambil") { rec.idAmbil = jam; rec.fotoIdambil = true; } else { rec.idKembali = jam; rec.fotoIdkembali = true; }
      await setAbs(env, tanggal, nik, rec);
      return J({ ok: true, nama: emp[NAMA], jam, aksi: b.aksi, tanggal });
    }
  }

  if (route.startsWith("kl/")) {
    if (route === "kl/login" && post) {
      const b = await req.json(), kode = String(b.kode || "").trim().toLowerCase();
      const k = /^[a-z0-9-]{2,20}$/.test(kode) ? await getKl(env, kode) : null;
      if (k && k.kunci && Date.now() < k.kunci) return J({ error: "Terlalu banyak percobaan salah. Coba lagi 15 menit lagi." }, 429);
      if (!(k && same(await pbk(String(b.sandi || ""), k.salt), k.hash))) {
        if (k) { k.gagal = (k.gagal || 0) + 1; if (k.gagal >= 5) { k.kunci = Date.now() + 15 * 60e3; k.gagal = 0; } await setKl(env, kode, k); }
        await sleep(700); return J({ error: "Kode klien atau kata sandi salah" }, 401);
      }
      k.gagal = 0; delete k.kunci; await setKl(env, kode, k);
      return J({ token: await scopedTok(env, "kl", kode), nama: k.nama });
    }
    const kode = await scopedAuth(req, env, "kl", /^[a-z0-9-]{2,20}$/);
    if (!kode) return J({ error: "Sesi habis. Silakan masuk lagi." }, 401);
    const k = await getKl(env, kode);
    if (!k) return J({ error: "Akun klien tidak ditemukan." }, 404);
    if (route === "kl/data" && get) return RAW(`{"nama":${JSON.stringify(k.nama)},"rows":${joinJ(await all(env, "SELECT v FROM mcu WHERE kode=?", kode))}}`);
    if (route === "kl/simpan" && post) {
      const { rows } = await req.json();
      if (!Array.isArray(rows) || rows.length > 100) return J({ error: "maks 100 baris per permintaan" }, 400);
      const ditolak = [], st = [];
      for (const r of rows) {
        const nik = String(r?.nik || "").replace(/\D/g, ""), nama = clean(r?.nama), s = String(r?.status || "");
        const sts = /^sudah/i.test(s) ? "Sudah" : /^belum/i.test(s) ? "Belum" : "", tg = String(r?.tanggal || "").trim();
        const tgOk = /^\d{4}-\d{2}-\d{2}$/.test(tg) && !isNaN(new Date(tg));
        const al = !isNik(nik) ? "NIK harus 16 digit" : !nama ? "nama kosong" : !sts ? "status MCU harus Sudah atau Belum" : tg && !tgOk ? "tanggal MCU tidak valid" : sts === "Sudah" && !tg ? "tanggal MCU wajib jika sudah MCU" : "";
        if (al) { ditolak.push({ nik: nik || "?", alasan: al }); continue; }
        st.push(env.DB.prepare("INSERT INTO mcu(kode,nik,v) VALUES(?,?,?) ON CONFLICT(kode,nik) DO UPDATE SET v=excluded.v").bind(kode, nik, JSON.stringify({ nik, nama, status: sts, tanggal: tg, keterangan: clean(r.keterangan).slice(0, 300), klien: kode, klienNama: k.nama, diperbarui: new Date().toISOString() })));
      }
      for (const c of chunk(st, 50)) await env.DB.batch(c);
      return J({ ok: true, saved: st.length, ditolak });
    }
    if (route === "kl/hapus" && post) {
      const { niks } = await req.json();
      if (!Array.isArray(niks) || niks.length > 50) return J({ error: "maks 50 per permintaan" }, 400);
      const ids = niks.filter(isNik);
      if (ids.length) await env.DB.batch(ids.map(n => env.DB.prepare("DELETE FROM mcu WHERE kode=? AND nik=?").bind(kode, n)));
      return J({ ok: true });
    }
  }

  if (!(await hrAuth(req, env))) return J({ error: "unauthorized" }, 401);

  if (route === "karyawan" && get) return RAW(joinJ(await all(env, "SELECT data FROM karyawan")));
  if (route === "import" && post) {
    const { rows } = await req.json();
    if (!Array.isArray(rows) || rows.length > 100) return J({ error: "maks 100 baris per permintaan" }, 400);
    const good = rows.filter(r => r && isNik(r[NIK]) && r[NAMA]);
    const cfg = await getCfg(env), olds = {};
    for (const part of chunk(good, 90)) (await all(env, `SELECT nik,data FROM karyawan WHERE nik IN (${part.map(() => "?").join(",")})`, ...part.map(r => r[NIK]))).forEach(x => olds[x.nik] = JSON.parse(x.data));
    const owner = new Map((await all(env, "SELECT nip,nik FROM karyawan WHERE nip IS NOT NULL")).map(x => [x.nip, x.nik]));
    const ditolak = [], st = [], seen = {};
    for (const r of good) {
      const nik = r[NIK], old = olds[nik] || {}, row = {};
      for (const k in r) if (k !== "berkas" && k !== "lengkap") row[k] = clean(r[k]);
      let nip = row["NIP Pegawai"] || "";
      if (nip) {
        if (!/^[\w.-]{1,30}$/.test(nip)) { ditolak.push({ nik, alasan: "format NIP tidak valid" }); continue; }
        if ((owner.get(nip) && owner.get(nip) !== nik) || (seen[nip] && seen[nip] !== nik)) { ditolak.push({ nik, alasan: `NIP ${nip} sudah dipakai karyawan lain` }); continue; }
        seen[nip] = nik; bump(cfg, nip);
      } else nip = old["NIP Pegawai"] || alloc(cfg, owner);
      row["NIP Pegawai"] = nip;
      if (old["NIP Pegawai"] && old["NIP Pegawai"] !== nip) owner.delete(old["NIP Pegawai"]);
      owner.set(nip, nik);
      st.push(karStmt(env, { ...old, ...row, diperbarui: new Date().toISOString() }));
    }
    for (const c of chunk(st, 50)) await env.DB.batch(c);
    await setCfg(env, cfg);
    return J({ ok: true, saved: st.length, ditolak });
  }
  if (route === "hapus" && post) {
    const { niks } = await req.json();
    if (!Array.isArray(niks) || niks.length > 50) return J({ error: "maks 50 per permintaan" }, 400);
    const ids = niks.filter(isNik);
    if (ids.length) await env.DB.batch(ids.flatMap(n => [env.DB.prepare("DELETE FROM karyawan WHERE nik=?").bind(n), env.DB.prepare("DELETE FROM akun WHERE nik=?").bind(n), env.DB.prepare("DELETE FROM berkas WHERE k LIKE ?").bind(`b/${n}/%`)]));
    return J({ ok: true, deleted: ids.length });
  }
  if (route === "absensi" && get) {
    const bulan = q.get("bulan") || "";
    if (!/^\d{4}-\d{2}$/.test(bulan)) return J({ error: "bulan tidak valid" }, 400);
    return RAW(joinJ(await all(env, "SELECT v FROM absensi WHERE tanggal LIKE ?", bulan + "-%")));
  }
  if (route === "izin" && post) {
    const b = await req.json();
    if (!isNik(b.nik) || !/^\d{4}-\d{2}-\d{2}$/.test(b.tanggal || "")) return J({ error: "bad request" }, 400);
    const emp = await getKar(env, b.nik);
    if (!emp) return J({ error: "karyawan tidak ditemukan" }, 404);
    const rec = (await getAbs(env, b.tanggal, b.nik)) || { nik: b.nik, nama: emp[NAMA], tanggal: b.tanggal };
    rec.izin = !!b.izin; await setAbs(env, b.tanggal, b.nik, rec);
    return J({ ok: true });
  }
  if (route === "selfie" && get) {
    const t = q.get("tanggal") || "", n = q.get("nik"), ak = q.get("aksi");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(t) || !isNik(n) || !["masuk", "pulang", "idambil", "idkembali"].includes(ak)) return J({ error: "bad request" }, 400);
    const f = await getFile(env, `s/${t}/${n}/${ak}`);
    return f ? J({ data: f }) : J({ error: "tidak ada" }, 404);
  }
  if (route === "berkas" && get) {
    const n = q.get("nik"), key = q.get("key");
    if (!isNik(n) || !KEYS.includes(key)) return J({ error: "bad request" }, 400);
    const f = await getFile(env, `b/${n}/${key}`);
    return f ? J({ data: f }) : J({ error: "tidak ada" }, 404);
  }
  if (route === "resetpin" && post) {
    const { niks } = await req.json();
    if (!Array.isArray(niks) || niks.length > 50) return J({ error: "maks 50 per permintaan" }, 400);
    const ids = niks.filter(isNik);
    if (ids.length) await env.DB.batch(ids.map(n => env.DB.prepare("DELETE FROM akun WHERE nik=?").bind(n)));
    return J({ ok: true, reset: ids.length });
  }
  if (route === "nip" && get) return J(await getCfg(env));
  if (route === "nip" && post) {
    const b = await req.json(), prefix = String(b.prefix ?? "").trim(), digits = Math.floor(+b.digits), next = Math.floor(+b.next);
    if (!/^[A-Za-z0-9._-]{0,10}$/.test(prefix)) return J({ error: "Awalan maks 10 karakter: huruf, angka, titik, minus" }, 400);
    if (!(digits >= 1 && digits <= 10) || !(next >= 1 && next < 1e9)) return J({ error: "Digit 1-10 dan nomor berikutnya harus angka positif" }, 400);
    await setCfg(env, { prefix, digits, next });
    return J({ ok: true });
  }
  if (route === "nip/isi" && post) {
    const cfg = await getCfg(env);
    const owner = new Map((await all(env, "SELECT nip,nik FROM karyawan WHERE nip IS NOT NULL")).map(x => [x.nip, x.nik]));
    const need = (await all(env, "SELECT data FROM karyawan WHERE nip IS NULL")).map(x => JSON.parse(x.data))
      .sort((x, y) => String(x["Timestamp Registrasi"] || "").localeCompare(String(y["Timestamp Registrasi"] || "")) || String(x[NAMA]).localeCompare(String(y[NAMA])));
    const batch = need.slice(0, 300);
    batch.forEach(r => { r["NIP Pegawai"] = alloc(cfg, owner); owner.set(r["NIP Pegawai"], r[NIK]); });
    for (const c of chunk(batch, 50)) await env.DB.batch(c.map(r => karStmt(env, r)));
    await setCfg(env, cfg);
    return J({ ok: true, diisi: batch.length, sisa: need.length - batch.length });
  }
  if (route === "mcu" && get) return RAW(joinJ(await all(env, "SELECT v FROM mcu")));
  if (route === "klien" && get) return J((await all(env, "SELECT v FROM klien")).map(x => JSON.parse(x.v)).map(k => ({ kode: k.kode, nama: k.nama })));
  if (route === "klien" && post) {
    const b = await req.json(), kode = String(b.kode || "").trim().toLowerCase(), nama = clean(b.nama), sandi = String(b.sandi || "");
    if (!/^[a-z0-9-]{2,20}$/.test(kode) || !nama) return J({ error: "Kode (huruf kecil, angka, minus; 2-20 karakter) dan nama wajib diisi" }, 400);
    const old = await getKl(env, kode);
    if ((!old || sandi) && sandi.length < 8) return J({ error: "Kata sandi minimal 8 karakter" }, 400);
    const rec = { ...(old || {}), kode, nama };
    if (sandi) { rec.salt = rnd(); rec.hash = await pbk(sandi, rec.salt); rec.gagal = 0; delete rec.kunci; }
    await setKl(env, kode, rec);
    return J({ ok: true, baru: !old });
  }
  if (route === "klien/hapus" && post) {
    const kode = String((await req.json()).kode || "");
    if (!/^[a-z0-9-]{2,20}$/.test(kode)) return J({ error: "kode tidak valid" }, 400);
    await env.DB.prepare("DELETE FROM klien WHERE kode=?").bind(kode).run();
    return J({ ok: true });
  }
  return J({ error: "not found" }, 404);
}
