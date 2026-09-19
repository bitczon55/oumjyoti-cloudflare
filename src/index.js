const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers
    }
  });

const now = () => new Date().toISOString();

const uid = () => crypto.randomUUID();

/* =========================================================
   BASIC HELPERS
========================================================= */

function b64(bytes) {
  let s = "";
  const arr = new Uint8Array(bytes);

  for (let i = 0; i < arr.length; i += 0x8000) {
    s += String.fromCharCode(...arr.subarray(i, i + 0x8000));
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

function input(v, max = 500) {
  return String(v ?? "")
    .trim()
    .slice(0, max);
}

function validEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
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

function requireRole(user, roles) {
  return Boolean(
    user && roles.includes(user.role)
  );
}

function maskAadhaar(v) {
  return v
    ? `XXXX-XXXX-${String(v).slice(-4)}`
    : "";
}

function maskPan(v) {
  return v
    ? `${String(v).slice(0, 2)}XXXX${String(v).slice(-2)}`
    : "";
}

/* =========================================================
   PASSWORD HASH
========================================================= */

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
  const result = await passwordHash(
    password,
    salt
  );

  return result.hash === hash;
}

/* =========================================================
   AES-256-GCM ENCRYPTION
========================================================= */

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
      {
        name: "AES-GCM"
      },
      false,
      ["encrypt"]
    );

  const iv =
    crypto.getRandomValues(
      new Uint8Array(12)
    );

  const ciphertext =
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

  return `${b64(iv)}.${b64(
    ciphertext
  )}`;
}

async function decryptText(
  payload,
  env
) {
  if (!payload) return "";

  const parts =
    payload.split(".");

  if (
    parts.length !== 2 ||
    !parts[0] ||
    !parts[1]
  ) {
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
      {
        name: "AES-GCM"
      },
      false,
      ["decrypt"]
    );

  const plaintext =
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: unb64(ivS)
      },
      key,
      unb64(ctS)
    );

  return new TextDecoder().decode(
    plaintext
  );
}

/* =========================================================
   COOKIE / SESSION
========================================================= */

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

/* =========================================================
   CREATE SESSION
========================================================= */

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
     (
       id,
       user_id,
       token_hash,
       expires_at,
       created_at
     )
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

/* =========================================================
   AUTH
========================================================= */

async function auth(
  request,
  env
) {
  const token =
    getSessionToken(request);

  if (!token) {
    return null;
  }

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
         AND u.status = 'active'
       LIMIT 1`
    )
      .bind(
        tokenHash,
        now()
      )
      .first();

  return row || null;
}

/* =========================================================
   ENSURE WEBSITE SETTINGS TABLE
   This allows website management without requiring
   another immediate manual migration.
========================================================= */

let websiteSchemaReady = false;

async function ensureWebsiteSchema(
  env
) {
  if (websiteSchemaReady) {
    return;
  }

  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS website_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL
    )`
  ).run();

  websiteSchemaReady = true;
}

/* =========================================================
   DEFAULT WEBSITE CONTENT
========================================================= */

const DEFAULT_SITE_CONTENT = {
  site_title:
    "OUMJYOTI — भक्ति • सेवा • मानवता",

  site_description:
    "OUMJYOTI — भक्ति, सेवा और मानवता का दिव्य संगम।",

  hero_title:
    "भक्ति से सेवा, सेवा से मानवता",

  hero_text:
    "OUMJYOTI का उद्देश्य भक्ति, सेवा और मानवता के माध्यम से जरूरतमंद लोगों, गौ माता, बुजुर्गों और समाज के कमजोर वर्गों तक सहयोग पहुँचाना है।",

  mission_title:
    "हमारा सेवा मिशन",

  mission_text:
    "गौ सेवा, अन्न दान, शिक्षा सहायता, स्वास्थ्य सहायता, बुजुर्ग सेवा और आपदा राहत जैसे सेवा कार्यों के माध्यम से समाज में सहयोग, करुणा और मानवता की भावना को मजबूत करना हमारा संकल्प है।",

  about_title:
    "OUMJYOTI के बारे में",

  about_text:
    "OUMJYOTI भक्ति, सेवा और मानवता को एक साथ जोड़ने वाला सेवा प्रयास है। हमारा लक्ष्य जरूरतमंद लोगों तक यथासंभव सहायता पहुँचाना और समाज में सेवा की भावना को बढ़ावा देना है।",

  operator_name:
    "परिचालक श्री टंक शर्मा",

  co_operator_name:
    "सहकारी परिचालना श्री छबिलाल ढकाल",

  contact_email:
    "",

  contact_mobile:
    "",

  hero_image:
    "/Images/hero.jpg",

  logo_image:
    "/oumjyoti-logo.png"
};

/* =========================================================
   GET WEBSITE CONTENT
========================================================= */

async function getWebsiteContent(
  env
) {
  await ensureWebsiteSchema(env);

  const rows =
    await env.DB.prepare(
      `SELECT key,value
       FROM website_settings`
    ).all();

  const content = {
    ...DEFAULT_SITE_CONTENT
  };

  for (
    const row of rows.results || []
  ) {
    content[row.key] =
      row.value;
  }

  return content;
}

/* =========================================================
   SAVE WEBSITE CONTENT
========================================================= */

async function saveWebsiteContent(
  env,
  data
) {
  await ensureWebsiteSchema(env);

  const allowedKeys =
    Object.keys(
      DEFAULT_SITE_CONTENT
    );

  for (
    const key of allowedKeys
  ) {
    if (
      data[key] === undefined
    ) {
      continue;
    }

    const value =
      input(
        data[key],
        key.includes("text")
          ? 5000
          : 1000
      );

    await env.DB.prepare(
      `INSERT INTO website_settings
       (key,value,updated_at)
       VALUES (?,?,?)
       ON CONFLICT(key)
       DO UPDATE SET
         value=excluded.value,
         updated_at=excluded.updated_at`
    )
      .bind(
        key,
        value,
        now()
      )
      .run();
  }
}

/* =========================================================
   R2 HELPERS
========================================================= */

const MAX_IMAGE_SIZE =
  10 * 1024 * 1024;

function safeImageName(
  name
) {
  const original =
    String(name || "image")
      .trim()
      .toLowerCase();

  const cleaned =
    original
      .replace(
        /[^a-z0-9._-]/g,
        "-"
      )
      .replace(
        /-+/g,
        "-"
      )
      .slice(0, 120);

  return cleaned || "image";
}

function extensionFromType(
  contentType
) {
  const map = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "image/gif": "gif",
    "image/avif": "avif"
  };

  return map[
    contentType
  ] || null;
}

function isAllowedImageType(
  contentType
) {
  return Boolean(
    extensionFromType(
      contentType
    )
  );
}

/* =========================================================
   PUBLIC R2 MEDIA
   Example:
   /media/home/hero.jpg
========================================================= */

async function serveR2Object(
  request,
  env
) {
  if (!env.IMAGES) {
    return new Response(
      "R2 is not configured",
      {
        status: 503
      }
    );
  }

  const url =
    new URL(request.url);

  let key =
    decodeURIComponent(
      url.pathname.replace(
        /^\/media\//,
        ""
      )
    );

  if (!key) {
    return new Response(
      "Image not found",
      {
        status: 404
      }
    );
  }

  key =
    key.replace(
      /^\/+/,
      ""
    );

  const object =
    await env.IMAGES.get(
      key
    );

  if (!object) {
    return new Response(
      "Image not found",
      {
        status: 404
      }
    );
  }

  const headers =
    new Headers();

  object.writeHttpMetadata(
    headers
  );

  headers.set(
    "etag",
    object.httpEtag
  );

  headers.set(
    "cache-control",
    "public, max-age=31536000, immutable"
  );

  if (
    request.method === "HEAD"
  ) {
    return new Response(
      null,
      {
        status: 200,
        headers
      }
    );
  }

  return new Response(
    object.body,
    {
      status: 200,
      headers
    }
  );
}

/* =========================================================
   API
========================================================= */

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

  /* =======================================================
     HEALTH
  ======================================================= */

  if (
    path === "/api/health" &&
    method === "GET"
  ) {
    return json({
      ok: true,
      service:
        "OUMJYOTI Seva",
      d1: Boolean(env.DB),
      r2: Boolean(env.IMAGES)
    });
  }

  /* =======================================================
     SETUP ADMIN
  ======================================================= */

  if (
    path === "/api/setup-admin" &&
    method === "POST"
  ) {
    const body =
      await request
        .json()
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
        `SELECT COUNT(*) AS n
         FROM users
         WHERE role='admin'`
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
      input(
        body.name,
        100
      );

    const place =
      input(
        body.place,
        100
      );

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
        "Admin created. Remove or rotate SETUP_KEY after setup."
    });
  }

  /* =======================================================
     REGISTER
  ======================================================= */

  if (
    path === "/api/register" &&
    method === "POST"
  ) {
    const b =
      await request
        .json()
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
        .replace(
          /\s/g,
          ""
        );

    const aadhaar =
      input(
        b.aadhaar,
        20
      ).replace(
        /\D/g,
        ""
      );

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
            "Please enter valid registration details. Password must be at least 8 characters."
        },
        400
      );
    }

    if (
      pan &&
      !/^[A-Z]{5}\d{4}[A-Z]$/.test(
        pan
      )
    ) {
      return json(
        {
          error:
            "PAN format is invalid"
        },
        400
      );
    }

    if (
      aadhaar &&
      !/^\d{12}$/.test(
        aadhaar
      )
    ) {
      return json(
        {
          error:
            "Aadhaar must contain 12 digits"
        },
        400
      );
    }

    const p =
      await passwordHash(
        password
      );

    try {
      const panEnc =
        pan
          ? await encryptText(
              pan,
              env
            )
          : null;

      const aadhaarEnc =
        aadhaar
          ? await encryptText(
              aadhaar,
              env
            )
          : null;

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
          pan_enc,
          aadhaar_enc,
          status,
          created_at,
          updated_at
        )
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
      )
        .bind(
          uid(),
          "member",
          name,
          place,
          email,
          mobile,
          p.hash,
          p.salt,
          panEnc,
          aadhaarEnc,
          "active",
          now(),
          now()
        )
        .run();

      return json(
        {
          ok: true,
          message:
            "Registration successful. You can now login."
        },
        201
      );
    } catch (e) {
      console.error(
        "REGISTER_ERROR:",
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
  }

  /* =======================================================
     LOGIN
  ======================================================= */

  if (
    path === "/api/login" &&
    method === "POST"
  ) {
    const b =
      await request
        .json()
        .catch(() => ({}));

    const mobile =
      input(
        b.mobile ||
          b.identifier,
        10
      );

    const password =
      b.password;

    if (
      !validMobile(mobile) ||
      !validPassword(password)
    ) {
      return json(
        {
          error:
            "Invalid login"
        },
        400
      );
    }

    const u =
      await env.DB.prepare(
        `SELECT
          id,
          role,
          name,
          place,
          email,
          mobile,
          password_hash,
          password_salt,
          status,
          staff_role
        FROM users
        WHERE mobile=?
        LIMIT 1`
      )
        .bind(mobile)
        .first();

    if (
      !u ||
      u.status !==
        "active" ||
      !(await verifyPassword(
        password,
        u.password_hash,
        u.password_salt
      ))
    ) {
      return json(
        {
          error:
            "Mobile number or password is incorrect"
        },
        401
      );
    }

    const token =
      await createSession(
        u.id,
        env
      );

    return json(
      {
        ok: true,
        user: {
          id: u.id,
          role: u.role,
          name: u.name,
          place: u.place,
          email: u.email,
          mobile: u.mobile,
          staffRole:
            u.staff_role
        }
      },
      200,
      {
        "set-cookie":
          cookie(
            "session",
            token,
            60 *
              60 *
              24 *
              7
          )
      }
    );
  }

  /* =======================================================
     LOGOUT
  ======================================================= */

  if (
    path === "/api/logout" &&
    method === "POST"
  ) {
    const token =
      getSessionToken(
        request
      );

    if (token) {
      await env.DB.prepare(
        `DELETE FROM sessions
         WHERE token_hash=?`
      )
        .bind(
          await sha256(token)
        )
        .run();
    }

    return json(
      {
        ok: true
      },
      200,
      {
        "set-cookie":
          clearCookie(
            "session"
          )
      }
    );
  }

  /* =======================================================
     CURRENT USER
  ======================================================= */

  if (
    path === "/api/me" &&
    method === "GET"
  ) {
    const currentUser =
      await auth(
        request,
        env
      );

    if (!currentUser) {
      return json({
        authenticated:
          false
      });
    }

    return json({
      authenticated:
        true,
      user: {
        id:
          currentUser.id,
        role:
          currentUser.role,
        name:
          currentUser.name,
        place:
          currentUser.place,
        email:
          currentUser.email,
        mobile:
          currentUser.mobile,
        staffRole:
          currentUser.staff_role
      }
    });
  }

  /* =======================================================
     PUBLIC WEBSITE CONTENT
  ======================================================= */

  if (
    path ===
      "/api/site-content" &&
    method === "GET"
  ) {
    try {
      const content =
        await getWebsiteContent(
          env
        );

      return json({
        ok: true,
        content
      });
    } catch (e) {
      console.error(
        "SITE_CONTENT_ERROR:",
        e
      );

      return json(
        {
          error:
            "Website content unavailable"
        },
        500
      );
    }
  }

  /* =======================================================
     PUBLIC SEVA
  ======================================================= */

  if (
    path === "/api/seva" &&
    method === "GET"
  ) {
    try {
      const rows =
        await env.DB.prepare(
          `SELECT
            id,
            title,
            description,
            image_url,
            icon,
            active,
            sort_order,
            created_at,
            updated_at
          FROM seva
          WHERE active=1
          ORDER BY
            sort_order ASC,
            created_at ASC`
        ).all();

      return json({
        seva:
          rows.results || []
      });
    } catch (e) {
      console.error(
        "PUBLIC_SEVA_ERROR:",
        e
      );

      return json(
        {
          error:
            "Seva service is not available"
        },
        500
      );
    }
  }

  /* =======================================================
     R2 PUBLIC IMAGE
  ======================================================= */

  if (
    path.startsWith(
      "/media/"
    ) &&
    (
      method === "GET" ||
      method === "HEAD"
    )
  ) {
    return serveR2Object(
      request,
      env
    );
  }

  /* =======================================================
     AUTH REQUIRED BELOW
  ======================================================= */

  const u =
    await auth(
      request,
      env
    );

  if (!u) {
    return json(
      {
        error:
          "Authentication required"
      },
      401
    );
  }

  /* =======================================================
     UPDATE PROFILE
  ======================================================= */

  if (
    path === "/api/me" &&
    method === "PUT"
  ) {
    const b =
      await request
        .json()
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

    if (
      !name ||
      !place ||
      !validEmail(email)
    ) {
      return json(
        {
          error:
            "Invalid profile"
        },
        400
      );
    }

    try {
      await env.DB.prepare(
        `UPDATE users
         SET
           name=?,
           place=?,
           email=?,
           updated_at=?
         WHERE id=?`
      )
        .bind(
          name,
          place,
          email,
          now(),
          u.id
        )
        .run();

      return json({
        ok: true
      });
    } catch (e) {
      console.error(
        "PROFILE_UPDATE_ERROR:",
        e
      );

      return json(
        {
          error:
            "Email is already in use"
        },
        409
      );
    }
  }

  /* =======================================================
     CHANGE PASSWORD
  ======================================================= */

  if (
    path === "/api/password" &&
    method === "PUT"
  ) {
    const b =
      await request
        .json()
        .catch(() => ({}));

    if (
      !validPassword(
        b.newPassword
      )
    ) {
      return json(
        {
          error:
            "New password must be at least 8 characters"
        },
        400
      );
    }

    const row =
      await env.DB.prepare(
        `SELECT
          password_hash,
          password_salt
         FROM users
         WHERE id=?`
      )
        .bind(
          u.id
        )
        .first();

    if (
      !row ||
      !(await verifyPassword(
        b.currentPassword ||
          "",
        row.password_hash,
        row.password_salt
      ))
    ) {
      return json(
        {
          error:
            "Current password is incorrect"
        },
        400
      );
    }

    const p =
      await passwordHash(
        b.newPassword
      );

    await env.DB.prepare(
      `UPDATE users
       SET
         password_hash=?,
         password_salt=?,
         updated_at=?
       WHERE id=?`
    )
      .bind(
        p.hash,
        p.salt,
        now(),
        u.id
      )
      .run();

    await env.DB.prepare(
      `DELETE FROM sessions
       WHERE user_id=?`
    )
      .bind(
        u.id
      )
      .run();

    return json(
      {
        ok: true,
        message:
          "Password changed. Please login again."
      },
      200,
      {
        "set-cookie":
          clearCookie(
            "session"
          )
      }
    );
  }

  /* =======================================================
     FEEDBACK
  ======================================================= */

  if (
    path ===
      "/api/feedback" &&
    method === "POST"
  ) {
    const b =
      await request
        .json()
        .catch(() => ({}));

    const mobile =
      input(
        b.mobile ||
          u.mobile,
        10
      );

    const email =
      input(
        b.email ||
          u.email,
        150
      ).toLowerCase();

    const message =
      input(
        b.message,
        2000
      );

    if (
      !validMobile(mobile) ||
      !validEmail(email) ||
      message.length < 3
    ) {
      return json(
        {
          error:
            "Please provide valid email, mobile and message"
        },
        400
      );
    }

    await env.DB.prepare(
      `INSERT INTO feedback
      (
        id,
        user_id,
        mobile,
        email,
        message,
        status,
        created_at
      )
      VALUES (?,?,?,?,?,?,?)`
    )
      .bind(
        uid(),
        u.id,
        mobile,
        email,
        message,
        "new",
        now()
      )
      .run();

    return json(
      {
        ok: true,
        message:
          "Feedback submitted"
      },
      201
    );
  }

  /* =======================================================
     ADMIN / STAFF MEMBERS LIST
  ======================================================= */

  if (
    path ===
      "/api/admin/members" &&
    method === "GET"
  ) {
    if (
      !requireRole(
        u,
        [
          "admin",
          "staff"
        ]
      )
    ) {
      return json(
        {
          error:
            "Forbidden"
        },
        403
      );
    }

    const rows =
      await env.DB.prepare(
        `SELECT
          id,
          role,
          name,
          place,
          email,
          mobile,
          status,
          staff_role,
          created_at,
          updated_at
        FROM users
        ORDER BY
          created_at DESC
        LIMIT 500`
      ).all();

    return json({
      members:
        rows.results || []
    });
  }

  /* =======================================================
     ADMIN CREATE MEMBER / STAFF
  ======================================================= */

  if (
    path ===
      "/api/admin/members" &&
    method === "POST"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    const b =
      await request
        .json()
        .catch(() => ({}));

    const name =
      input(b.name, 100);

    const place =
      input(
        b.place,
        100
      );

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

    const role =
      [
        "member",
        "staff"
      ].includes(
        b.role
      )
        ? b.role
        : "member";

    const staffRole =
      input(
        b.staffRole,
        100
      );

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
            "Invalid details"
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
          staff_role,
          created_at,
          updated_at
        )
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
      )
        .bind(
          uid(),
          role,
          name,
          place,
          email,
          mobile,
          p.hash,
          p.salt,
          "active",
          role === "staff"
            ? staffRole
            : null,
          now(),
          now()
        )
        .run();

      return json(
        {
          ok: true,
          message:
            `${role === "staff" ? "Staff" : "Member"} created successfully`
        },
        201
      );
    } catch (e) {
      console.error(
        "ADMIN_MEMBER_CREATE_ERROR:",
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
  }

  /* =======================================================
     ADMIN ENABLE / DISABLE MEMBER OR STAFF
  ======================================================= */

  const memberMatch =
    path.match(
      /^\/api\/admin\/members\/([^/]+)$/
    );

  if (
    memberMatch &&
    method === "PATCH"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    const id =
      memberMatch[1];

    const b =
      await request
        .json()
        .catch(() => ({}));

    const status =
      b.status ===
      "disabled"
        ? "disabled"
        : "active";

    if (
      id === u.id &&
      status ===
        "disabled"
    ) {
      return json(
        {
          error:
            "You cannot disable your own admin account"
        },
        400
      );
    }

    const result =
      await env.DB.prepare(
        `UPDATE users
         SET
           status=?,
           updated_at=?
         WHERE id=?`
      )
        .bind(
          status,
          now(),
          id
        )
        .run();

    if (
      !result.meta?.changes
    ) {
      return json(
        {
          error:
            "Member not found"
        },
        404
      );
    }

    if (
      status ===
      "disabled"
    ) {
      await env.DB.prepare(
        `DELETE FROM sessions
         WHERE user_id=?`
      )
        .bind(id)
        .run();
    }

    return json({
      ok: true,
      status
    });
  }

  /* =======================================================
     ADMIN / STAFF FEEDBACK LIST
  ======================================================= */

  if (
    path ===
      "/api/admin/feedback" &&
    method === "GET"
  ) {
    if (
      !requireRole(
        u,
        [
          "admin",
          "staff"
        ]
      )
    ) {
      return json(
        {
          error:
            "Forbidden"
        },
        403
      );
    }

    const rows =
      await env.DB.prepare(
        `SELECT
          f.id,
          f.user_id,
          f.mobile,
          f.email,
          f.message,
          f.status,
          f.created_at,
          u.name,
          u.role
        FROM feedback f
        LEFT JOIN users u
          ON u.id=f.user_id
        ORDER BY
          f.created_at DESC
        LIMIT 500`
      ).all();

    return json({
      feedback:
        rows.results || []
    });
  }

  /* =======================================================
     ADMIN / STAFF MARK FEEDBACK
  ======================================================= */

  if (
    path ===
      "/api/admin/feedback/read" &&
    method === "POST"
  ) {
    if (
      !requireRole(
        u,
        [
          "admin",
          "staff"
        ]
      )
    ) {
      return json(
        {
          error:
            "Forbidden"
        },
        403
      );
    }

    const b =
      await request
        .json()
        .catch(() => ({}));

    const id =
      input(
        b.id,
        100
      );

    const status =
      [
        "new",
        "read",
        "resolved"
      ].includes(
        b.status
      )
        ? b.status
        : "read";

    if (!id) {
      return json(
        {
          error:
            "Feedback ID required"
        },
        400
      );
    }

    const result =
      await env.DB.prepare(
        `UPDATE feedback
         SET status=?
         WHERE id=?`
      )
        .bind(
          status,
          id
        )
        .run();

    if (
      !result.meta?.changes
    ) {
      return json(
        {
          error:
            "Feedback not found"
        },
        404
      );
    }

    return json({
      ok: true,
      status
    });
  }

  /* =======================================================
     ADMIN VIEW MASKED PAN / AADHAAR
  ======================================================= */

  if (
    path ===
      "/api/admin/member-sensitive" &&
    method === "POST"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    const b =
      await request
        .json()
        .catch(() => ({}));

    const id =
      input(
        b.id,
        100
      );

    if (!id) {
      return json(
        {
          error:
            "Member ID is required"
        },
        400
      );
    }

    const row =
      await env.DB.prepare(
        `SELECT
          pan_enc,
          aadhaar_enc
         FROM users
         WHERE id=?
         LIMIT 1`
      )
        .bind(id)
        .first();

    if (!row) {
      return json(
        {
          error:
            "Member not found"
        },
        404
      );
    }

    let pan = "";
    let aadhaar = "";

    try {
      pan =
        row.pan_enc
          ? await decryptText(
              row.pan_enc,
              env
            )
          : "";
    } catch (e) {
      console.error(
        "PAN_DECRYPT_ERROR:",
        e
      );
    }

    try {
      aadhaar =
        row.aadhaar_enc
          ? await decryptText(
              row.aadhaar_enc,
              env
            )
          : "";
    } catch (e) {
      console.error(
        "AADHAAR_DECRYPT_ERROR:",
        e
      );
    }

    return json({
      pan: maskPan(
        pan
      ),
      aadhaar:
        maskAadhaar(
          aadhaar
        )
    });
  }

  /* =======================================================
     ADMIN SEVA LIST
  ======================================================= */

  if (
    path ===
      "/api/admin/seva" &&
    method === "GET"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    const rows =
      await env.DB.prepare(
        `SELECT
          id,
          title,
          description,
          image_url,
          icon,
          active,
          sort_order,
          created_at,
          updated_at
        FROM seva
        ORDER BY
          sort_order ASC,
          created_at ASC`
      ).all();

    return json({
      seva:
        rows.results || []
    });
  }

  /* =======================================================
     ADMIN ADD SEVA
  ======================================================= */

  if (
    path ===
      "/api/admin/seva" &&
    method === "POST"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    const b =
      await request
        .json()
        .catch(() => ({}));

    const title =
      input(
        b.title,
        150
      );

    const description =
      input(
        b.description,
        2000
      );

    const imageUrl =
      input(
        b.image_url,
        1000
      );

    const icon =
      input(
        b.icon ||
          "🕉️",
        20
      );

    const active =
      b.active === false ||
      b.active === 0 ||
      b.active === "0"
        ? 0
        : 1;

    let sortOrder =
      Number.isFinite(
        Number(
          b.sort_order
        )
      )
        ? Number(
            b.sort_order
          )
        : 0;

    sortOrder =
      Math.max(
        0,
        Math.min(
          999999,
          Math.floor(
            sortOrder
          )
        )
      );

    if (!title) {
      return json(
        {
          error:
            "Seva name/title is required"
        },
        400
      );
    }

    const id =
      uid();

    await env.DB.prepare(
      `INSERT INTO seva
      (
        id,
        title,
        description,
        image_url,
        icon,
        active,
        sort_order,
        created_at,
        updated_at
      )
      VALUES (?,?,?,?,?,?,?,?,?)`
    )
      .bind(
        id,
        title,
        description,
        imageUrl,
        icon,
        active,
        sortOrder,
        now(),
        now()
      )
      .run();

    return json(
      {
        ok: true,
        id
      },
      201
    );
  }

  /* =======================================================
     ADMIN EDIT SEVA
  ======================================================= */

  const sevaMatch =
    path.match(
      /^\/api\/admin\/seva\/([^/]+)$/
    );

  if (
    sevaMatch &&
    method === "PATCH"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    const id =
      sevaMatch[1];

    const existing =
      await env.DB.prepare(
        `SELECT *
         FROM seva
         WHERE id=?
         LIMIT 1`
      )
        .bind(id)
        .first();

    if (!existing) {
      return json(
        {
          error:
            "Seva not found"
        },
        404
      );
    }

    const b =
      await request
        .json()
        .catch(() => ({}));

    const title =
      b.title !==
      undefined
        ? input(
            b.title,
            150
          )
        : existing.title;

    const description =
      b.description !==
      undefined
        ? input(
            b.description,
            2000
          )
        : existing.description;

    const imageUrl =
      b.image_url !==
      undefined
        ? input(
            b.image_url,
            1000
          )
        : existing.image_url;

    const icon =
      b.icon !==
      undefined
        ? input(
            b.icon,
            20
          )
        : existing.icon;

    const active =
      b.active !==
      undefined
        ? (
            b.active ===
              false ||
            b.active ===
              0 ||
            b.active ===
              "0"
          )
          ? 0
          : 1
        : Number(
            existing.active
          );

    let sortOrder =
      b.sort_order !==
      undefined
        ? Number(
            b.sort_order
          )
        : Number(
            existing.sort_order
          );

    if (
      !Number.isFinite(
        sortOrder
      )
    ) {
      sortOrder =
        Number(
          existing.sort_order
        ) || 0;
    }

    sortOrder =
      Math.max(
        0,
        Math.min(
          999999,
          Math.floor(
            sortOrder
          )
        )
      );

    if (!title) {
      return json(
        {
          error:
            "Seva name/title is required"
        },
        400
      );
    }

    await env.DB.prepare(
      `UPDATE seva
       SET
         title=?,
         description=?,
         image_url=?,
         icon=?,
         active=?,
         sort_order=?,
         updated_at=?
       WHERE id=?`
    )
      .bind(
        title,
        description,
        imageUrl,
        icon,
        active,
        sortOrder,
        now(),
        id
      )
      .run();

    return json({
      ok: true,
      id
    });
  }

  /* =======================================================
     ADMIN DELETE SEVA
  ======================================================= */

  if (
    sevaMatch &&
    method === "DELETE"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    const id =
      sevaMatch[1];

    const existing =
      await env.DB.prepare(
        `SELECT
          id
         FROM seva
         WHERE id=?
         LIMIT 1`
      )
        .bind(id)
        .first();

    if (!existing) {
      return json(
        {
          error:
            "Seva not found"
        },
        404
      );
    }

    await env.DB.prepare(
      `DELETE FROM seva
       WHERE id=?`
    )
      .bind(id)
      .run();

    return json({
      ok: true
    });
  }

  /* =======================================================
     ADMIN WEBSITE CONTENT GET
  ======================================================= */

  if (
    path ===
      "/api/admin/site-content" &&
    method === "GET"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    const content =
      await getWebsiteContent(
        env
      );

    return json({
      ok: true,
      content
    });
  }

  /* =======================================================
     ADMIN WEBSITE CONTENT UPDATE
  ======================================================= */

  if (
    path ===
      "/api/admin/site-content" &&
    method === "PUT"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    const b =
      await request
        .json()
        .catch(() => ({}));

    await saveWebsiteContent(
      env,
      b
    );

    const content =
      await getWebsiteContent(
        env
      );

    return json({
      ok: true,
      message:
        "Website content updated successfully",
      content
    });
  }

  /* =======================================================
     ADMIN IMAGE UPLOAD TO R2
     
     POST /api/admin/upload
     
     multipart/form-data:
       file = image
       folder = website / seva / gallery
       name = optional filename
  ======================================================= */

  if (
    path ===
      "/api/admin/upload" &&
    method === "POST"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    if (!env.IMAGES) {
      return json(
        {
          error:
            "R2 IMAGES binding is not configured"
        },
        503
      );
    }

    const contentType =
      request.headers.get(
        "content-type"
      ) || "";

    if (
      !contentType
        .toLowerCase()
        .startsWith(
          "multipart/form-data"
        )
    ) {
      return json(
        {
          error:
            "Please upload using multipart/form-data"
        },
        400
      );
    }

    const form =
      await request.formData();

    const file =
      form.get("file");

    const folderRaw =
      input(
        form.get("folder") ||
          "website",
        50
      ).toLowerCase();

    const allowedFolders = [
      "website",
      "seva",
      "gallery",
      "logo"
    ];

    const folder =
      allowedFolders.includes(
        folderRaw
      )
        ? folderRaw
        : "website";

    if (
      !file ||
      typeof file ===
        "string" ||
      typeof file.arrayBuffer !==
        "function"
    ) {
      return json(
        {
          error:
            "Image file is required"
        },
        400
      );
    }

    if (
      !isAllowedImageType(
        file.type
      )
    ) {
      return json(
        {
          error:
            "Only JPG, PNG, WEBP, GIF or AVIF images are allowed"
        },
        400
      );
    }

    if (
      file.size >
      MAX_IMAGE_SIZE
    ) {
      return json(
        {
          error:
            "Image size must not exceed 10 MB"
        },
        400
      );
    }

    const ext =
      extensionFromType(
        file.type
      );

    const suppliedName =
      input(
        form.get("name") ||
          file.name ||
          "image",
        120
      );

    let cleanName =
      safeImageName(
        suppliedName
      );

    cleanName =
      cleanName.replace(
        /\.[a-z0-9]+$/i,
        ""
      );

    if (!cleanName) {
      cleanName =
        "image";
    }

    const key =
      `${folder}/${Date.now()}-${crypto.randomUUID()}.${ext}`;

    const arrayBuffer =
      await file.arrayBuffer();

    await env.IMAGES.put(
      key,
      arrayBuffer,
      {
        httpMetadata: {
          contentType:
            file.type,
          cacheControl:
            "public, max-age=31536000, immutable"
        },
        customMetadata: {
          uploadedBy:
            String(
              u.id
            ),
          originalName:
            String(
              file.name ||
                cleanName
            ).slice(
              0,
              200
            )
        }
      }
    );

    return json(
      {
        ok: true,
        key,
        url:
          `/media/${encodeURIComponent(
            key
          ).replace(
            /%2F/g,
            "/"
          )}`,
        size:
          file.size,
        type:
          file.type
      },
      201
    );
  }

  /* =======================================================
     ADMIN R2 IMAGE DELETE
     
     DELETE /api/admin/upload?key=website/example.jpg
  ======================================================= */

  if (
    path ===
      "/api/admin/upload" &&
    method === "DELETE"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    if (!env.IMAGES) {
      return json(
        {
          error:
            "R2 IMAGES binding is not configured"
        },
        503
      );
    }

    const key =
      url.searchParams.get(
        "key"
      );

    if (!key) {
      return json(
        {
          error:
            "Image key is required"
        },
        400
      );
    }

    const cleanKey =
      key
        .replace(
          /^\/+/,
          ""
        )
        .slice(
          0,
          500
        );

    if (
      cleanKey.includes(
        ".."
      )
    ) {
      return json(
        {
          error:
            "Invalid image key"
        },
        400
      );
    }

    await env.IMAGES.delete(
      cleanKey
    );

    return json({
      ok: true,
      message:
        "Image deleted"
    });
  }

  /* =======================================================
     ADMIN R2 IMAGE CHECK
     
     GET /api/admin/upload?key=...
  ======================================================= */

  if (
    path ===
      "/api/admin/upload" &&
    method === "GET"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    if (!env.IMAGES) {
      return json(
        {
          error:
            "R2 IMAGES binding is not configured"
        },
        503
      );
    }

    const key =
      url.searchParams.get(
        "key"
      );

    if (!key) {
      return json(
        {
          error:
            "Image key is required"
        },
        400
      );
    }

    const object =
      await env.IMAGES.head(
        key
      );

    if (!object) {
      return json(
        {
          exists: false
        },
        404
      );
    }

    return json({
      exists: true,
      key,
      size:
        object.size,
      etag:
        object.etag,
      uploaded:
        object.uploaded
    });
  }

  /* =======================================================
     ADMIN R2 LIST
     
     GET /api/admin/images?prefix=website/
  ======================================================= */

  if (
    path ===
      "/api/admin/images" &&
    method === "GET"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    if (!env.IMAGES) {
      return json(
        {
          error:
            "R2 IMAGES binding is not configured"
        },
        503
      );
    }

    const prefix =
      input(
        url.searchParams.get(
          "prefix"
        ) || "",
        200
      );

    const listed =
      await env.IMAGES.list({
        prefix,
        limit: 100
      });

    const images =
      (listed.objects || [])
        .map(
          (object) => ({
            key:
              object.key,
            size:
              object.size,
            uploaded:
              object.uploaded,
            etag:
              object.etag,
            url:
              `/media/${object.key}`
          })
        );

    return json({
      ok: true,
      images,
      truncated:
        Boolean(
          listed.truncated
        )
    });
  }

  /* =======================================================
     ADMIN DASHBOARD STATS
  ======================================================= */

  if (
    path ===
      "/api/admin/stats" &&
    method === "GET"
  ) {
    if (
      u.role !== "admin"
    ) {
      return json(
        {
          error:
            "Admin only"
        },
        403
      );
    }

    const members =
      await env.DB.prepare(
        `SELECT COUNT(*) AS n
         FROM users
         WHERE role='member'`
      ).first();

    const staff =
      await env.DB.prepare(
        `SELECT COUNT(*) AS n
         FROM users
         WHERE role='staff'`
      ).first();

    const activeMembers =
      await env.DB.prepare(
        `SELECT COUNT(*) AS n
         FROM users
         WHERE role IN ('member','staff')
           AND status='active'`
      ).first();

    const feedback =
      await env.DB.prepare(
        `SELECT COUNT(*) AS n
         FROM feedback
         WHERE status='new'`
      ).first();

    const seva =
      await env.DB.prepare(
        `SELECT COUNT(*) AS n
         FROM seva
         WHERE active=1`
      ).first();

    return json({
      ok: true,
      stats: {
        members:
          Number(
            members?.n || 0
          ),
        staff:
          Number(
            staff?.n || 0
          ),
        active:
          Number(
            activeMembers?.n ||
              0
          ),
        newFeedback:
          Number(
            feedback?.n || 0
          ),
        activeSeva:
          Number(
            seva?.n || 0
          )
      }
    });
  }

  /* =======================================================
     UNKNOWN API
  ======================================================= */

  return json(
    {
      error:
        "API route not found"
    },
    404
  );
}

/* =========================================================
   WORKER
========================================================= */

export default {
  async fetch(
    request,
    env
  ) {
    const url =
      new URL(request.url);

    try {
      /* R2 media must be served before ASSETS */
      if (
        url.pathname.startsWith(
          "/media/"
        )
      ) {
        if (
          request.method ===
            "GET" ||
          request.method ===
            "HEAD"
        ) {
          return await serveR2Object(
            request,
            env
          );
        }
      }

      if (
        url.pathname.startsWith(
          "/api/"
        )
      ) {
        return await api(
          request,
          env
        );
      }

      if (
        env.ASSETS &&
        typeof env.ASSETS.fetch ===
          "function"
      ) {
        return await env.ASSETS.fetch(
          request
        );
      }

      return new Response(
        "OUMJYOTI website is running.",
        {
          status: 200,
          headers: {
            "content-type":
              "text/plain; charset=utf-8"
          }
        }
      );
    } catch (error) {
      console.error(
        "WORKER_ERROR:",
        error
      );

      if (
        url.pathname.startsWith(
          "/api/"
        )
      ) {
        return json(
          {
            error:
              "Internal server error"
          },
          500
        );
      }

      if (
        url.pathname.startsWith(
          "/media/"
        )
      ) {
        return new Response(
          "Image service error",
          {
            status: 500
          }
        );
      }

      return new Response(
        "Internal Server Error",
        {
          status: 500
        }
      );
    }
  }
};
