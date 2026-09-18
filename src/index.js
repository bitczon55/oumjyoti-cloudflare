const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...headers
    }
  });

const now = () => new Date().toISOString();

const uid = () => crypto.randomUUID();

/* =========================
   BASE64 HELPERS
========================= */

function b64(bytes) {
  let s = "";
  const arr = new Uint8Array(bytes);

  for (let i = 0; i < arr.length; i += 0x8000) {
    s += String.fromCharCode(
      ...arr.subarray(i, i + 0x8000)
    );
  }

  return btoa(s);
}

function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);

  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }

  return out;
}

/* =========================
   HASH
========================= */

async function sha256(text) {
  const d = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );

  return b64(d);
}

async function randomB64(n = 32) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return b64(a);
}

/* =========================
   PASSWORD
========================= */

async function passwordHash(password, saltB64) {
  const salt = saltB64
    ? unb64(saltB64)
    : crypto.getRandomValues(
        new Uint8Array(16)
      );

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return {
    hash: b64(bits),
    salt: b64(salt)
  };
}

async function verifyPassword(
  password,
  hash,
  salt
) {
  const r = await passwordHash(
    password,
    salt
  );

  return r.hash === hash;
}

/* =========================
   ENCRYPTION
========================= */

function getEncryptionKey(env) {
  if (!env.APP_ENCRYPTION_KEY) {
    throw new Error(
      "APP_ENCRYPTION_KEY is not configured"
    );
  }

  const keyBytes = unb64(
    env.APP_ENCRYPTION_KEY
  );

  if (keyBytes.length !== 32) {
    throw new Error(
      "APP_ENCRYPTION_KEY must be base64 for exactly 32 bytes"
    );
  }

  return keyBytes;
}

async function encryptText(
  plaintext,
  env
) {
  const keyBytes =
    getEncryptionKey(env);

  const key =
    await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

  const iv =
    crypto.getRandomValues(
      new Uint8Array(12)
    );

  const ct =
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      new TextEncoder().encode(
        plaintext
      )
    );

  return `${b64(iv)}.${b64(ct)}`;
}

async function decryptText(
  payload,
  env
) {
  if (!payload) return "";

  const parts =
    payload.split(".");

  if (parts.length !== 2) {
    throw new Error(
      "Invalid encrypted payload"
    );
  }

  const [ivS, ctS] = parts;

  const keyBytes =
    getEncryptionKey(env);

  const key =
    await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

  const pt =
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: unb64(ivS)
      },
      key,
      unb64(ctS)
    );

  return new TextDecoder().decode(
    pt
  );
}

/* =========================
   COOKIE
========================= */

function cookie(
  name,
  value,
  maxAge
) {
  return `${name}=${encodeURIComponent(
    value
  )}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookie(name) {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

/* =========================
   INPUT VALIDATION
========================= */

function input(v, max = 500) {
  return String(v ?? "")
    .trim()
    .slice(0, max);
}

function validEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    v
  );
}

function validMobile(v) {
  return /^[6-9]\d{9}$/.test(v);
}

function validPassword(v) {
  return (
    typeof v === "string" &&
    v.length >= 8 &&
    v.length <= 128
  );
}

function maskAadhaar(v) {
  return v
    ? `XXXX-XXXX-${v.slice(-4)}`
    : "";
}

function maskPan(v) {
  return v
    ? `${v.slice(0, 2)}XXXX${v.slice(-2)}`
    : "";
}

/* =========================
   SESSION
========================= */

function getSessionToken(request) {
  const cookieHeader =
    request.headers.get("Cookie") || "";

  const match =
    cookieHeader.match(
      /(?:^|;\s*)session=([^;]+)/
    );

  return match
    ? decodeURIComponent(match[1])
    : null;
}

async function createSession(
  userId,
  env
) {
  const raw =
    await randomB64(32);

  const hash =
    await sha256(raw);

  const expires =
    new Date(
      Date.now() +
        1000 *
          60 *
          60 *
          24 *
          7
    ).toISOString();

  await env.DB.prepare(
    `INSERT INTO sessions
     (id,user_id,token_hash,expires_at,created_at)
     VALUES (?,?,?,?,?)`
  )
    .bind(
      uid(),
      userId,
      hash,
      expires,
      now()
    )
    .run();

  return raw;
}

async function auth(
  request,
  env
) {
  const token =
    getSessionToken(request);

  if (!token) return null;

  const tokenHash =
    await sha256(token);

  const row =
    await env.DB.prepare(
      `SELECT
         u.id,
         u.role,
         u.name,
         u.place,
         u.email,
         u.mobile,
         u.status,
         u.staff_role,
         s.expires_at
       FROM sessions s
       JOIN users u
         ON u.id = s.user_id
       WHERE s.token_hash = ?
         AND s.expires_at > ?
         AND u.status = 'active'`
    )
      .bind(
        tokenHash,
        now()
      )
      .first();

  return row || null;
}

function requireRole(
  user,
  roles
) {
  return Boolean(
    user &&
      roles.includes(user.role)
  );
}

/* =========================
   API
========================= */

async function api(
  request,
  env
) {
  const url =
    new URL(request.url);

  const path =
    url.pathname;

  const method =
    request.method;

  /* =========================
     HEALTH
  ========================== */

  if (
    path === "/api/health" &&
    method === "GET"
  ) {
    return json({
      ok: true,
      service:
        "OUMJYOTI Seva"
    });
  }

  /* =========================
     SETUP ADMIN
  ========================== */

  if (
    path === "/api/setup-admin" &&
    method === "POST"
  ) {
    const body =
      await request.json()
        .catch(() => ({}));

    if (
      !env.SETUP_KEY ||
      body.setupKey !==
        env.SETUP_KEY
    ) {
      return json(
        {
          error:
            "Invalid setup key"
        },
        403
      );
    }

    const existing =
      await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM users WHERE role='admin'"
      ).first();

    if (
      Number(
        existing?.n || 0
      ) > 0
    ) {
      return json(
        {
          error:
            "Admin already exists"
        },
        409
      );
    }

    const name =
      input(body.name, 100);

    const place =
      input(body.place, 100);

    const email =
      input(
        body.email,
        150
      ).toLowerCase();

    const mobile =
      input(
        body.mobile,
        10
      );

    const password =
      body.password;

    if (
      !name ||
      !place ||
      !validEmail(email) ||
      !validMobile(mobile) ||
      !validPassword(password)
    ) {
      return json(
        {
          error:
            "Invalid admin details. Password must be at least 8 characters."
        },
        400
      );
    }

    const p =
      await passwordHash(
        password
      );

    try {
      await env.DB.prepare(
        `INSERT INTO users
        (
          id,
          role,
          name,
          place,
          email,
          mobile,
          password_hash,
          password_salt,
          status,
          created_at,
          updated_at
        )
        VALUES (?,?,?,?,?,?,?,?,?,?,?)`
      )
        .bind(
          uid(),
          "admin",
          name,
          place,
          email,
          mobile,
          p.hash,
          p.salt,
          "active",
          now(),
          now()
        )
        .run();
    } catch (e) {
      console.error(
        "SETUP_ADMIN_ERROR:",
        e
      );

      return json(
        {
          error:
            "Email or mobile already exists"
        },
        409
      );
    }

    return json({
      ok: true,
      message:
        "Admin created successfully."
    });
  }

  /* =========================
     REGISTER
  ========================== */

  if (
    path === "/api/register" &&
    method === "POST"
  ) {
    const b =
      await request.json()
        .catch(() => ({}));

    const name =
      input(b.name, 100);

    const place =
      input(b.place, 100);

    const email =
      input(
        b.email,
        150
      ).toLowerCase();

    const mobile =
      input(
        b.mobile,
        10
      );

    const password =
      b.password;

    const pan =
      input(
        b.pan,
        20
      )
        .toUpperCase()
        .replace(/\s/g, "");

    const
