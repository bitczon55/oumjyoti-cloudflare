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

async function passwordHash(password, saltB64) {
  const salt = saltB64
    ? unb64(saltB64)
    : crypto.randomBytes
      ? crypto.randomBytes(16)
      : crypto.getRandomValues(new Uint8Array(16));

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

async function verifyPassword(password, hash, salt) {
  const r = await passwordHash(password, salt);
  return r.hash === hash;
}

function getEncryptionKey(env) {
  if (!env.APP_ENCRYPTION_KEY) {
    throw new Error("APP_ENCRYPTION_KEY is not configured");
  }

  const keyBytes = unb64(env.APP_ENCRYPTION_KEY);

  if (keyBytes.length !== 32) {
    throw new Error(
      "APP_ENCRYPTION_KEY must be base64 for exactly 32 bytes"
    );
  }

  return keyBytes;
}

async function encryptText(plaintext, env) {
  const keyBytes = getEncryptionKey(env);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ct = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    new TextEncoder().encode(plaintext)
  );

  return `${b64(iv)}.${b64(ct)}`;
}

async function decryptText(payload, env) {
  if (!payload) return "";

  const parts = payload.split(".");

  if (parts.length !== 2) {
    throw new Error("Invalid encrypted payload");
  }

  const [ivS, ctS] = parts;

  const keyBytes = getEncryptionKey(env);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const pt = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: unb64(ivS)
    },
    key,
    unb64(ctS)
  );

  return new TextDecoder().decode(pt);
}

function cookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(
    value
  )}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookie(name) {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
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

function maskAadhaar(v) {
  return v ? `XXXX-XXXX-${v.slice(-4)}` : "";
}

function maskPan(v) {
  return v ? `${v.slice(0, 2)}XXXX${v.slice(-2)}` : "";
}

function getSessionToken(request) {
  const cookieHeader =
    request.headers.get("Cookie") || "";

  const match = cookieHeader.match(
    /(?:^|;\s*)session=([^;]+)/
  );

  return match
    ? decodeURIComponent(match[1])
    : null;
}

async function createSession(userId, env) {
  const raw = await randomB64(32);
  const hash = await sha256(raw);

  const expires = new Date(
    Date.now() + 1000 * 60 * 60 * 24 * 7
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

async function auth(request, env) {
  const token = getSessionToken(request);

  if (!token) return null;

  const tokenHash = await sha256(token);

  const row = await env.DB.prepare(
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
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?
       AND s.expires_at > ?
       AND u.status = 'active'`
  )
    .bind(tokenHash, now())
    .first();

  return row || null;
}

function requireRole(user, roles) {
  return Boolean(
    user && roles.includes(user.role)
  );
}

async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  /* =========================
     HEALTH
  ========================== */

  if (
    path === "/api/health" &&
    method === "GET"
  ) {
    return json({
      ok: true,
      service: "OUMJYOTI Seva"
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
      await request.json().catch(() => ({}));

    if (
      !env.SETUP_KEY ||
      body.setupKey !== env.SETUP_KEY
    ) {
      return json(
        { error: "Invalid setup key" },
        403
      );
    }

    const existing =
      await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM users WHERE role='admin'"
      ).first();

    if (Number(existing?.n || 0) > 0) {
      return json(
        { error: "Admin already exists" },
        409
      );
    }

    const name = input(body.name, 100);
    const place = input(body.place, 100);
    const email =
      input(body.email, 150).toLowerCase();
    const mobile = input(body.mobile, 10);
    const password = body.password;

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

    const p = await passwordHash(password);

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

  /* =========================
     REGISTER
  ========================== */

  if (
    path === "/api/register" &&
    method === "POST"
  ) {
    const b =
      await request.json().catch(() => ({}));

    const name = input(b.name, 100);
    const place = input(b.place, 100);
    const email =
      input(b.email, 150).toLowerCase();
    const mobile = input(b.mobile, 10);
    const password = b.password;

    const pan = input(b.pan, 20)
      .toUpperCase()
      .replace(/\s/g, "");

    const aadhaar = input(b.aadhaar, 20)
      .replace(/\D/g, "");

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
      !/^[A-Z]{5}\d{4}[A-Z]$/.test(pan)
    ) {
      return json(
        {
          error: "PAN format is invalid"
        },
        400
      );
    }

    if (
      aadhaar &&
      !/^\d{12}$/.test(aadhaar)
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
      await passwordHash(password);

    try {
      const panEnc = pan
        ? await encryptText(pan, env)
        : null;

      const aadhaarEnc = aadhaar
        ? await encryptText(aadhaar, env)
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

  /* =========================
     LOGIN
  ========================== */

  if (
    path === "/api/login" &&
    method === "POST"
  ) {
    const b =
      await request.json().catch(() => ({}));

    const mobile =
      input(b.mobile, 10);

    const password = b.password;

    if (
      !validMobile(mobile) ||
      !validPassword(password)
    ) {
      return json(
        { error: "Invalid login" },
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
        WHERE mobile=?`
      )
        .bind(mobile)
        .first();

    if (
      !u ||
      u.status !== "active" ||
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
      await createSession(u.id, env);

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
          staffRole: u.staff_role
        }
      },
      200,
      {
        "set-cookie": cookie(
          "session",
          token,
          60 * 60 * 24 * 7
        )
      }
    );
  }

  /* =========================
     LOGOUT
  ========================== */

  if (
    path === "/api/logout" &&
    method === "POST"
  ) {
    const token =
      getSessionToken(request);

    if (token) {
      await env.DB.prepare(
        "DELETE FROM sessions WHERE token_hash=?"
      )
        .bind(await sha256(token))
        .run();
    }

    return json(
      { ok: true },
      200,
      {
        "set-cookie":
          clearCookie("session")
      }
    );
  }

  /* =========================
     CURRENT USER
  ========================== */

  if (
    path === "/api/me" &&
    method === "GET"
  ) {
    const currentUser =
      await auth(request, env);

    if (!currentUser) {
      return json({
        authenticated: false
      });
    }

    return json({
      authenticated: true,
      user: {
        id: currentUser.id,
        role: currentUser.role,
        name: currentUser.name,
        place: currentUser.place,
        email: currentUser.email,
        mobile: currentUser.mobile,
        staffRole: currentUser.staff_role
      }
    });
  }

  /* =========================
     PUBLIC SEVA
  ========================== */

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
          WHERE active = 1
          ORDER BY sort_order ASC, created_at ASC`
        ).all();

      return json({
        seva: rows.results || []
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

  /* =========================
     AUTH REQUIRED BELOW
  ========================== */

  const u = await auth(
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

  /* =========================
     UPDATE PROFILE
  ========================== */

  if (
    path === "/api/me" &&
    method === "PUT"
  ) {
    const b =
      await request.json().catch(() => ({}));

    const name = input(b.name, 100);
    const place = input(b.place, 100);
    const email =
      input(b.email, 150).toLowerCase();

    if (
      !name ||
      !place ||
      !validEmail(email)
    ) {
      return json(
        {
          error: "Invalid profile"
        },
        400
      );
    }

    try {
      await env.DB.prepare(
        `UPDATE users
         SET name=?,
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

  /* =========================
     CHANGE PASSWORD
  ========================== */

  if (
    path === "/api/password" &&
    method === "PUT"
  ) {
    const b =
      await request.json().catch(() => ({}));

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
        .bind(u.id)
        .first();

    if (
      !row ||
      !(await verifyPassword(
        b.currentPassword || "",
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
       SET password_hash=?,
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
      "DELETE FROM sessions WHERE user_id=?"
    )
      .bind(u.id)
      .run();

    return json(
      { ok: true },
      200,
      {
        "set-cookie":
          clearCookie("session")
      }
    );
  }

  /* =========================
     FEEDBACK
  ========================== */

  if (
    path === "/api/feedback" &&
    method === "POST"
  ) {
    const b =
      await request.json().catch(() => ({}));

    const mobile =
      input(
        b.mobile || u.mobile,
        10
      );

    const email =
      input(
        b.email || u.email,
        150
      ).toLowerCase();

    const message =
      input(b.message, 2000);

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

  /* =========================
     ADMIN / STAFF MEMBERS
  ========================== */

  if (
    path === "/api/admin/members" &&
    method === "GET"
  ) {
    if (
      !requireRole(u, [
        "admin",
        "staff"
      ])
    ) {
      return json(
        { error: "Forbidden" },
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
          created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT 500`
      ).all();

    return json({
      members:
        rows.results || []
    });
  }

  /* =========================
     ADMIN CREATE MEMBER/STAFF
  ========================== */

  if (
    path === "/api/admin/members" &&
    method === "POST"
  ) {
    if (u.role !== "admin") {
      return json(
        { error: "Admin only" },
        403
      );
    }

    const b =
      await request.json().catch(() => ({}));

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
      input(b.mobile, 10);

    const password =
      b.password;

    const role =
      ["member", "staff"].includes(
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
      await passwordHash(password);

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
        { ok: true },
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

  /* =========================
     ADMIN ENABLE / DISABLE
  ========================== */

  const memberMatch =
    path.match(
      /^\/api\/admin\/members\/([^/]+)$/
    );

  if (
    memberMatch &&
    method === "PATCH"
  ) {
    if (u.role !== "admin") {
      return json(
        { error: "Admin only" },
        403
      );
    }

    const id =
      memberMatch[1];

    const b =
      await request.json().catch(() => ({}));

    const status =
      b.status === "disabled"
        ? "disabled"
        : "active";

    if (
      id === u.id &&
      status === "disabled"
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
         SET status=?,
             updated_at=?
         WHERE id=?`
      )
        .bind(
          status,
          now(),
          id
        )
        .run();

    if (!result.meta?.changes) {
      return json(
        {
          error:
            "Member not found"
        },
        404
      );
    }

    return json({
      ok: true,
      status
    });
  }

  /* =========================
     ADMIN FEEDBACK LIST
  ========================== */

  if (
    path === "/api/admin/feedback" &&
    method === "GET"
  ) {
    if (u.role !== "admin") {
      return json(
        { error: "Admin only" },
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
          ON u.id = f.user_id
        ORDER BY f.created_at DESC
        LIMIT 500`
      ).all();

    return json({
      feedback:
        rows.results || []
    });
  }

  /* =========================
     ADMIN MARK FEEDBACK READ
  ========================== */

  if (
    path === "/api/admin/feedback/read" &&
    method === "POST"
  ) {
    if (u.role !== "admin") {
      return json(
        { error: "Admin only" },
        403
      );
    }

    const b =
      await request.json().catch(() => ({}));

    const id =
      input(b.id, 100);

    if (!id) {
      return json(
        {
          error:
            "Feedback ID required"
        },
        400
      );
    }

    await env.DB.prepare(
      `UPDATE feedback
       SET status='read'
       WHERE id=?`
    )
      .bind(id)
      .run();

    return json({
      ok: true
    });
  }

  /* =========================
     ADMIN SEVA LIST
  ========================== */

  if (
    path === "/api/admin/seva" &&
    method === "GET"
  ) {
    if (u.role !== "admin") {
      return json(
        { error: "Admin only" },
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
        ORDER BY sort_order ASC, created_at ASC`
      ).all();

    return json({
      seva:
        rows.results || []
    });
  }

  /* =========================
     ADMIN ADD SEVA
  ========================== */

  if (
    path === "/api/admin/seva" &&
    method === "POST"
  ) {
    if (u.role !== "admin") {
      return json(
        { error: "Admin only" },
        403
      );
    }

    const b =
      await request.json().catch(() => ({}));

    const title =
      input(b.title, 150);

    const description =
      input(b.description, 2000);

    const imageUrl =
      input(b.image_url, 1000);

    const icon =
      input(b.icon || "🕉️", 20);

    const active =
      b.active === false ||
      b.active === 0 ||
      b.active === "0"
        ? 0
        : 1;

    let sortOrder =
      Number.isFinite(
        Number(b.sort_order)
      )
        ? Number(b.sort_order)
        : 0;

    sortOrder =
      Math.max(
        0,
        Math.min(
          999999,
          Math.floor(sortOrder)
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

  /* =========================
     ADMIN EDIT SEVA
  ========================== */

  const sevaMatch =
    path.match(
      /^\/api\/admin\/seva\/([^/]+)$/
    );

  if (
    sevaMatch &&
    method === "PATCH"
  ) {
    if (u.role !== "admin") {
      return json(
        { error: "Admin only" },
        403
      );
    }

    const id =
      sevaMatch[1];

    const existing =
      await env.DB.prepare(
        `SELECT *
         FROM seva
         WHERE id=?`
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
      await request.json().catch(() => ({}));

    const title =
      b.title !== undefined
        ? input(b.title, 150)
        : existing.title;

    const description =
      b.description !== undefined
        ? input(b.description, 2000)
        : existing.description;

    const imageUrl =
      b.image_url !== undefined
        ? input(b.image_url, 1000)
        : existing.image_url;

    const icon =
      b.icon !== undefined
        ? input(b.icon, 20)
        : existing.icon;

    const active =
      b.active !== undefined
        ? (
            b.active === false ||
            b.active === 0 ||
            b.active === "0"
              ? 0
              : 1
          )
        : Number(existing.active);

    let sortOrder =
      b.sort_order !== undefined
        ? Number(b.sort_order)
        : Number(existing.sort_order);

    if (!Number.isFinite(sortOrder)) {
      sortOrder = Number(existing.sort_order) || 0;
    }

    sortOrder =
      Math.max(
        0,
        Math.min(
          999999,
          Math.floor(sortOrder)
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
       SET title=?,
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

  /* =========================
     ADMIN DELETE SEVA
  ========================== */

  if (
    sevaMatch &&
    method === "DELETE"
  ) {
    if (u.role !== "admin") {
      return json(
        { error: "Admin only" },
        403
      );
    }

    const id =
      sevaMatch[1];

    const existing =
      await env.DB.prepare(
        `SELECT id
         FROM seva
         WHERE id=?`
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

  /* =========================
     UNKNOWN API
  ========================== */

  return json(
    {
      error:
        "API route not found"
    },
    404
  );
}

/* =========================
   WORKER
========================= */

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    try {
      if (
        url.pathname.startsWith("/api/")
      ) {
        return await api(
          request,
          env
        );
      }

      if (
        env.ASSETS &&
        typeof env.ASSETS.fetch === "function"
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
        url.pathname.startsWith("/api/")
      ) {
        return json(
          {
            error:
              "Internal server error"
          },
          500
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
