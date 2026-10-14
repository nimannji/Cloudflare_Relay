import { connect } from "cloudflare:sockets";

const DEFAULT_TARGET = "77.90.45.197:2053";
const DEFAULT_UUID = "915ad98f-2a94-4ef6-8f70-cc8cdf37cf15";

const SECRET_PATH = "/mysecretpath";

const PANEL_PATH = "/panel";
const NORMAL_SUB_PATH = "/sub";
const PATT_MCI_SUB_PATH = "/patt-mci-sub";
const PATT_IRANCELL_SUB_PATH = "/patt-irancell-sub";

const KV_TARGET_KEY = "upstream";
const KV_UUID_KEY = "uuid";
const KV_CLEAN_HOSTS_KEY = "clean_ips";

const SESSION_COOKIE = "panel_session";
const SESSION_TTL_SECONDS = 12 * 60 * 60;

/* =========================================================
   PATT MCI SETTINGS

   - No cipherSuites
   - Fingerprint = chrome
   - ECH enabled
   - No finalMask
   ========================================================= */

const PATT_MCI_FINGERPRINT = "chrome";
const PATT_MCI_ALPN = "http/1.1";

const PATT_MCI_ECH_CONFIG_LIST =
  "cloudflare-ech.com+udp://1.1.1.1";

/* =========================================================
   PATT IRANCELL SETTINGS

   - Cipher suites enabled
   - Fingerprint = unsafe
   - No ECH
   - finalMask enabled
   ========================================================= */

const PATT_IRANCELL_FINGERPRINT = "unsafe";
const PATT_IRANCELL_ALPN = "http/1.1";

const PATT_IRANCELL_CIPHER_SUITES =
  "TLS_AES_256_GCM_SHA384:" +
  "TLS_CHACHA20_POLY1305_SHA256:" +
  "TLS_AES_128_GCM_SHA256:" +
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:" +
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:" +
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:" +
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:" +
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:" +
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:" +
  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:" +
  "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:" +
  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:" +
  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";

const PATT_IRANCELL_FINAL_MASK = {
  tcp: [
    {
      type: "fragment",
      settings: {
        packets: "tlshello",
        lengths: ["0", "104", "1"],
        delays: ["0"],
        maxSplit: "0",
      },
    },
    {
      type: "fragment",
      settings: {
        packets: "1-1",
        lengths: ["114", "1"],
        delays: ["1"],
        maxSplit: "11",
      },
    },
  ],
};

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const upgrade = request.headers.get("Upgrade");

      /* =====================================================
         WebSocket relay
         ===================================================== */

      if (
        url.pathname === SECRET_PATH &&
        upgrade?.toLowerCase() === "websocket"
      ) {
        const error = validateKvBinding(env);

        return error
          ? textResponse(error, 500)
          : handleWebSocket(env);
      }

      if (url.pathname === SECRET_PATH) {
        return textResponse(
          "WebSocket upgrade required",
          426,
        );
      }

      /* =====================================================
         Normal subscription
         ===================================================== */

      if (
        request.method === "GET" &&
        url.pathname.startsWith(
          `${NORMAL_SUB_PATH}/`,
        )
      ) {
        const error = validateKvBinding(env);

        return error
          ? textResponse(error, 500)
          : handleTextSubscription(
              request,
              env,
              NORMAL_SUB_PATH,
              "normal",
            );
      }

      /* =====================================================
         Patt MCI subscription
         ===================================================== */

      if (
        request.method === "GET" &&
        url.pathname.startsWith(
          `${PATT_MCI_SUB_PATH}/`,
        )
      ) {
        const error = validateKvBinding(env);

        return error
          ? textResponse(error, 500)
          : handleTextSubscription(
              request,
              env,
              PATT_MCI_SUB_PATH,
              "mci",
            );
      }

      /* =====================================================
         Patt Irancell subscription
         ===================================================== */

      if (
        request.method === "GET" &&
        url.pathname.startsWith(
          `${PATT_IRANCELL_SUB_PATH}/`,
        )
      ) {
        const error = validateKvBinding(env);

        return error
          ? textResponse(error, 500)
          : handleTextSubscription(
              request,
              env,
              PATT_IRANCELL_SUB_PATH,
              "irancell",
            );
      }

      /* =====================================================
         /panel/ -> /panel
         ===================================================== */

      if (
        request.method === "GET" &&
        url.pathname === `${PANEL_PATH}/`
      ) {
        return redirectResponse(
          PANEL_PATH,
          308,
        );
      }

      /* =====================================================
         Main panel
         ===================================================== */

      if (
        request.method === "GET" &&
        url.pathname === PANEL_PATH
      ) {
        const error = validatePanel(env);

        if (error) {
          return textResponse(
            error,
            500,
          );
        }

        const loggedIn =
          await isAuthenticated(
            request,
            env.admin,
          );

        if (!loggedIn) {
          return htmlResponse(
            renderLoginPage(),
          );
        }

        return htmlResponse(
          await renderPanelFromStorage(
            request,
            env,
          ),
        );
      }

      /* =====================================================
         Login
         ===================================================== */

      if (
        request.method === "POST" &&
        url.pathname ===
          `${PANEL_PATH}/login`
      ) {
        const error = validatePanel(env);

        return error
          ? textResponse(error, 500)
          : handleLogin(
              request,
              env,
            );
      }

      /* =====================================================
         Save
         ===================================================== */

      if (
        request.method === "POST" &&
        url.pathname ===
          `${PANEL_PATH}/save`
      ) {
        const error = validatePanel(env);

        return error
          ? textResponse(error, 500)
          : handleSave(
              request,
              env,
            );
      }

      /* =====================================================
         VPS TCP test
         ===================================================== */

      if (
        request.method === "POST" &&
        url.pathname ===
          `${PANEL_PATH}/test`
      ) {
        const error = validatePanel(env);

        return error
          ? textResponse(error, 500)
          : handleTest(
              request,
              env,
            );
      }

      /* =====================================================
         Logout
         ===================================================== */

      if (
        request.method === "POST" &&
        url.pathname ===
          `${PANEL_PATH}/logout`
      ) {
        const error = validatePanel(env);

        return error
          ? textResponse(error, 500)
          : handleLogout(
              request,
              env,
            );
      }

      return textResponse(
        "Not found",
        404,
      );
    } catch (error) {
      console.error(
        "Worker error:",
        error,
      );

      return textResponse(
        "Internal error",
        500,
      );
    }
  },
};

/* =========================================================
   VALIDATION
   ========================================================= */

function validateKvBinding(env) {
  if (
    !env?.kv ||
    typeof env.kv.get !== "function" ||
    typeof env.kv.put !== "function" ||
    typeof env.kv.delete !== "function"
  ) {
    return (
      "Missing KV binding. Bind the namespace using " +
      'the exact variable name "kv".'
    );
  }

  return null;
}

function validatePanel(env) {
  const kvError =
    validateKvBinding(env);

  if (kvError) {
    return kvError;
  }

  if (
    typeof env?.admin !== "string" ||
    !env.admin.length
  ) {
    return (
      "Missing panel password. Add a Plaintext variable " +
      'or Secret named "admin".'
    );
  }

  return null;
}

/* =========================================================
   SUBSCRIPTIONS
   ========================================================= */

async function validateSubscriptionUuid(
  request,
  env,
  basePath,
) {
  const url =
    new URL(request.url);

  let suppliedUuid;

  try {
    suppliedUuid =
      decodeURIComponent(
        url.pathname.slice(
          `${basePath}/`.length,
        ),
      );
  } catch {
    return null;
  }

  const currentUuid =
    await getCurrentUuid(env);

  if (
    !parseUuid(suppliedUuid) ||
    !(
      await safeEqualStrings(
        suppliedUuid.toLowerCase(),
        currentUuid,
      )
    )
  ) {
    return null;
  }

  return currentUuid;
}

async function handleTextSubscription(
  request,
  env,
  basePath,
  mode,
) {
  const currentUuid =
    await validateSubscriptionUuid(
      request,
      env,
      basePath,
    );

  if (!currentUuid) {
    return textResponse(
      "Not found",
      404,
    );
  }

  const url =
    new URL(request.url);

  const cleanHostsText =
    await getCurrentCleanHostsText(
      env,
    );

  let links;

  if (mode === "mci") {
    links =
      buildPattMciLinks(
        currentUuid,
        url.hostname,
        cleanHostsText,
      );
  } else if (
    mode === "irancell"
  ) {
    links =
      buildPattIrancellLinks(
        currentUuid,
        url.hostname,
        cleanHostsText,
      );
  } else {
    links =
      buildNormalLinks(
        currentUuid,
        url.hostname,
        cleanHostsText,
      );
  }

  return new Response(
    toBase64(
      links.join("\n"),
    ),
    {
      headers: {
        "Content-Type":
          "text/plain; charset=UTF-8",

        "Cache-Control":
          "no-store",

        "Access-Control-Allow-Origin":
          "*",

        "X-Content-Type-Options":
          "nosniff",
      },
    },
  );
}

/* =========================================================
   ADDRESS LIST

   Clean IP/domain entries are stored WITHOUT a port.

   Every clean entry automatically uses port 443.
   ========================================================= */

function buildAddressList(
  workerHostname,
  cleanText,
) {
  const workerHost =
    String(
      workerHostname,
    )
      .trim()
      .toLowerCase();

  const addresses = [
    {
      hostname:
        workerHost,

      port:
        443,
    },
  ];

  const clean =
    parseCleanHosts(
      cleanText,
    );

  if (clean.ok) {
    for (
      const hostname
      of clean.values
    ) {
      addresses.push({
        hostname,

        port:
          443,
      });
    }
  }

  return {
    workerHost,
    addresses,
  };
}

/* =========================================================
   NORMAL LINKS

   Names:
   Normal01
   Normal02
   ...
   ========================================================= */

function buildNormalLinks(
  uuid,
  workerHostname,
  cleanText,
) {
  const {
    workerHost,
    addresses,
  } =
    buildAddressList(
      workerHostname,
      cleanText,
    );

  return addresses.map(
    (
      item,
      index,
    ) => {
      const name =
        `Normal${
          String(
            index + 1,
          ).padStart(
            2,
            "0",
          )
        }`;

      return (
        `vless://${uuid}` +
        `@${item.hostname}:${item.port}` +

        `?security=tls` +

        `&sni=${
          encodeURIComponent(
            workerHost,
          )
        }` +

        `&type=ws` +

        `&path=${
          encodeURIComponent(
            SECRET_PATH,
          )
        }` +

        `&host=${
          encodeURIComponent(
            workerHost,
          )
        }` +

        `&encryption=none` +

        `#${
          encodeURIComponent(
            name,
          )
        }`
      );
    },
  );
}

/* =========================================================
   PATT MCI LINKS

   Names:
   MCI01
   MCI02
   ...

   - NO cipherSuites parameter
   - ECH enabled
   - fingerprint = chrome
   - NO finalMask
   ========================================================= */

function buildPattMciLinks(
  uuid,
  workerHostname,
  cleanText,
) {
  const {
    workerHost,
    addresses,
  } =
    buildAddressList(
      workerHostname,
      cleanText,
    );

  return addresses.map(
    (
      item,
      index,
    ) => {
      const name =
        `MCI${
          String(
            index + 1,
          ).padStart(
            2,
            "0",
          )
        }`;

      return (
        `vless://${uuid}` +
        `@${item.hostname}:${item.port}` +

        `?path=${
          encodeURIComponent(
            SECRET_PATH,
          )
        }` +

        `&security=tls` +

        `&alpn=${
          encodeURIComponent(
            PATT_MCI_ALPN,
          )
        }` +

        `&encryption=none` +

        `&ech=${
          encodeURIComponent(
            PATT_MCI_ECH_CONFIG_LIST,
          )
        }` +

        `&insecure=0` +

        `&host=${
          encodeURIComponent(
            workerHost,
          )
        }` +

        `&fp=${
          encodeURIComponent(
            PATT_MCI_FINGERPRINT,
          )
        }` +

        `&type=ws` +

        `&allowInsecure=0` +

        `&sni=${
          encodeURIComponent(
            workerHost,
          )
        }` +

        `#${
          encodeURIComponent(
            name,
          )
        }`
      );
    },
  );
}

/* =========================================================
   PATT IRANCELL LINKS

   Names:
   Icell01
   Icell02
   ...

   - Cipher suites kept
   - ECH removed
   - fingerprint = unsafe
   - finalMask enabled
   ========================================================= */

function buildPattIrancellLinks(
  uuid,
  workerHostname,
  cleanText,
) {
  const {
    workerHost,
    addresses,
  } =
    buildAddressList(
      workerHostname,
      cleanText,
    );

  const finalMask =
    JSON.stringify(
      PATT_IRANCELL_FINAL_MASK,
    );

  return addresses.map(
    (
      item,
      index,
    ) => {
      const name =
        `Icell${
          String(
            index + 1,
          ).padStart(
            2,
            "0",
          )
        }`;

      return (
        `vless://${uuid}` +
        `@${item.hostname}:${item.port}` +

        `?cs=${
          encodeURIComponent(
            PATT_IRANCELL_CIPHER_SUITES,
          )
        }` +

        `&path=${
          encodeURIComponent(
            SECRET_PATH,
          )
        }` +

        `&security=tls` +

        `&alpn=${
          encodeURIComponent(
            PATT_IRANCELL_ALPN,
          )
        }` +

        `&encryption=none` +

        `&fm=${
          encodeURIComponent(
            finalMask,
          )
        }` +

        `&insecure=0` +

        `&host=${
          encodeURIComponent(
            workerHost,
          )
        }` +

        `&fp=${
          encodeURIComponent(
            PATT_IRANCELL_FINGERPRINT,
          )
        }` +

        `&type=ws` +

        `&allowInsecure=0` +

        `&sni=${
          encodeURIComponent(
            workerHost,
          )
        }` +

        `#${
          encodeURIComponent(
            name,
          )
        }`
      );
    },
  );
}

/* =========================================================
   SUBSCRIPTION URLS
   ========================================================= */

function normalSubscriptionUrl(
  request,
  uuid,
) {
  const url =
    new URL(request.url);

  return (
    `${url.origin}` +
    `${NORMAL_SUB_PATH}/` +
    `${encodeURIComponent(uuid)}`
  );
}

function pattMciSubscriptionUrl(
  request,
  uuid,
) {
  const url =
    new URL(request.url);

  return (
    `${url.origin}` +
    `${PATT_MCI_SUB_PATH}/` +
    `${encodeURIComponent(uuid)}`
  );
}

function pattIrancellSubscriptionUrl(
  request,
  uuid,
) {
  const url =
    new URL(request.url);

  return (
    `${url.origin}` +
    `${PATT_IRANCELL_SUB_PATH}/` +
    `${encodeURIComponent(uuid)}`
  );
}

function toBase64(
  value,
) {
  const bytes =
    new TextEncoder()
      .encode(
        value,
      );

  let binary =
    "";

  for (
    const byte of bytes
  ) {
    binary +=
      String.fromCharCode(
        byte,
      );
  }

  return btoa(
    binary,
  );
}

/* =========================================================
   LOGIN
   ========================================================= */

async function handleLogin(
  request,
  env,
) {
  if (
    !isSameOriginRequest(
      request,
    )
  ) {
    return textResponse(
      "Invalid request origin",
      403,
    );
  }

  const form =
    await request.formData();

  const password =
    String(
      form.get("password") ?? "",
    );

  if (
    !(
      await safeEqualStrings(
        password,
        env.admin,
      )
    )
  ) {
    return htmlResponse(
      renderLoginPage(
        "Incorrect password.",
      ),
      401,
    );
  }

  const token =
    await createSessionToken(
      env.admin,
    );

  return new Response(
    null,
    {
      status:
        303,

      headers:
        secureHeaders({
          Location:
            PANEL_PATH,

          "Set-Cookie":
            makeSessionCookie(
              token,
              SESSION_TTL_SECONDS,
            ),
        }),
    },
  );
}

/* =========================================================
   LOGOUT
   ========================================================= */

async function handleLogout(
  request,
  env,
) {
  if (
    !(
      await isAuthenticated(
        request,
        env.admin,
      )
    )
  ) {
    return redirectResponse(
      PANEL_PATH,
    );
  }

  if (
    !isSameOriginRequest(
      request,
    )
  ) {
    return textResponse(
      "Invalid request origin",
      403,
    );
  }

  return new Response(
    null,
    {
      status:
        303,

      headers:
        secureHeaders({
          Location:
            PANEL_PATH,

          "Set-Cookie":
            makeSessionCookie(
              "",
              0,
            ),
        }),
    },
  );
}

/* =========================================================
   SAVE SETTINGS
   ========================================================= */

async function handleSave(
  request,
  env,
) {
  if (
    !(
      await isAuthenticated(
        request,
        env.admin,
      )
    )
  ) {
    return redirectResponse(
      PANEL_PATH,
    );
  }

  if (
    !isSameOriginRequest(
      request,
    )
  ) {
    return textResponse(
      "Invalid request origin",
      403,
    );
  }

  const form =
    await request.formData();

  const targetText =
    String(
      form.get("target") ?? "",
    ).trim();

  const uuidText =
    String(
      form.get("uuid") ?? "",
    ).trim();

  const cleanText =
    String(
      form.get("clean_ips") ?? "",
    );

  const target =
    parseIPv4Port(
      targetText,
    );

  const uuid =
    parseUuid(
      uuidText,
    );

  const clean =
    parseCleanHosts(
      cleanText,
    );

  if (!target) {
    return htmlResponse(
      renderPanel(
        request,
        targetText,
        uuidText,
        cleanText,
        "Enter a valid VPS IPv4:port.",
        true,
      ),
      400,
    );
  }

  if (!uuid) {
    return htmlResponse(
      renderPanel(
        request,
        `${target.hostname}:${target.port}`,
        uuidText,
        cleanText,
        "Enter a valid UUID.",
        true,
      ),
      400,
    );
  }

  if (!clean.ok) {
    return htmlResponse(
      renderPanel(
        request,
        `${target.hostname}:${target.port}`,
        uuid,
        cleanText,
        clean.error,
        true,
      ),
      400,
    );
  }

  const normalizedTarget =
    `${target.hostname}:` +
    `${target.port}`;

  const normalizedClean =
    clean.values.join("\n");

  await Promise.all([
    env.kv.put(
      KV_TARGET_KEY,
      normalizedTarget,
    ),

    env.kv.put(
      KV_UUID_KEY,
      uuid,
    ),

    normalizedClean
      ? env.kv.put(
          KV_CLEAN_HOSTS_KEY,
          normalizedClean,
        )
      : env.kv.delete(
          KV_CLEAN_HOSTS_KEY,
        ),
  ]);

  return htmlResponse(
    renderPanel(
      request,
      normalizedTarget,
      uuid,
      normalizedClean,
      "Settings saved. Subscriptions updated.",
      false,
    ),
  );
}

/* =========================================================
   VPS TCP TEST
   ========================================================= */

async function handleTest(
  request,
  env,
) {
  if (
    !(
      await isAuthenticated(
        request,
        env.admin,
      )
    )
  ) {
    return redirectResponse(
      PANEL_PATH,
    );
  }

  if (
    !isSameOriginRequest(
      request,
    )
  ) {
    return textResponse(
      "Invalid request origin",
      403,
    );
  }

  const [
    targetText,
    uuid,
    cleanText,
  ] =
    await Promise.all([
      getCurrentTarget(
        env,
      ),

      getCurrentUuid(
        env,
      ),

      getCurrentCleanHostsText(
        env,
      ),
    ]);

  const target =
    parseIPv4Port(
      targetText,
    );

  if (!target) {
    return htmlResponse(
      renderPanel(
        request,
        targetText,
        uuid,
        cleanText,
        "Saved destination is invalid.",
        true,
      ),
      500,
    );
  }

  const result =
    await testTcpConnection(
      target.hostname,
      target.port,
      5000,
    );

  const message =
    result.ok
      ? (
          "TCP connection successful: " +
          `${targetText} — ` +
          `${result.elapsedMs} ms`
        )
      : (
          "TCP connection failed after " +
          `${result.elapsedMs} ms: ` +
          result.error
        );

  return htmlResponse(
    renderPanel(
      request,
      targetText,
      uuid,
      cleanText,
      message,
      !result.ok,
    ),
  );
}

/* =========================================================
   LOAD PANEL SETTINGS
   ========================================================= */

async function renderPanelFromStorage(
  request,
  env,
) {
  const [
    target,
    uuid,
    cleanText,
  ] =
    await Promise.all([
      getCurrentTarget(
        env,
      ),

      getCurrentUuid(
        env,
      ),

      getCurrentCleanHostsText(
        env,
      ),
    ]);

  return renderPanel(
    request,
    target,
    uuid,
    cleanText,
  );
}

/* =========================================================
   KV GETTERS
   ========================================================= */

async function getCurrentTarget(
  env,
) {
  const stored =
    await env.kv.get(
      KV_TARGET_KEY,
    );

  return (
    typeof stored === "string" &&
    parseIPv4Port(stored)
  )
    ? stored.trim()
    : DEFAULT_TARGET;
}

async function getCurrentUuid(
  env,
) {
  const stored =
    await env.kv.get(
      KV_UUID_KEY,
    );

  return (
    parseUuid(stored) ||
    DEFAULT_UUID
  );
}

async function getCurrentCleanHostsText(
  env,
) {
  const stored =
    await env.kv.get(
      KV_CLEAN_HOSTS_KEY,
    );

  const parsed =
    parseCleanHosts(
      typeof stored === "string"
        ? stored
        : "",
    );

  return parsed.ok
    ? parsed.values.join("\n")
    : "";
}

/* =========================================================
   WEBSOCKET -> VPS TCP
   ========================================================= */

async function handleWebSocket(
  env,
) {
  const target =
    parseIPv4Port(
      await getCurrentTarget(
        env,
      ),
    );

  if (!target) {
    return textResponse(
      "Invalid upstream destination",
      500,
    );
  }

  const pair =
    new WebSocketPair();

  const client =
    pair[0];

  const server =
    pair[1];

  server.accept();

  bridgeWebSocketToTcp(
    server,
    target.hostname,
    target.port,
  ).catch(
    (error) => {
      console.error(
        "Bridge error:",
        error,
      );

      try {
        if (
          server.readyState ===
          WebSocket.OPEN
        ) {
          server.close(
            1011,
            "Backend connection failed",
          );
        }
      } catch {}
    },
  );

  return new Response(
    null,
    {
      status:
        101,

      webSocket:
        client,
    },
  );
}

async function bridgeWebSocketToTcp(
  webSocket,
  hostname,
  port,
) {
  const socket =
    connect({
      hostname,
      port,
    });

  await socket.opened;

  const writer =
    socket.writable
      .getWriter();

  const reader =
    socket.readable
      .getReader();

  let closed =
    false;

  let pendingWrite =
    Promise.resolve();

  const closeEverything =
    async (
      code = 1000,
      reason = "Connection closed",
      waitForWrites = true,
    ) => {
      if (closed) {
        return;
      }

      closed =
        true;

      if (waitForWrites) {
        try {
          await pendingWrite;
        } catch {}
      }

      try {
        writer.releaseLock();
      } catch {}

      try {
        reader.releaseLock();
      } catch {}

      try {
        await socket.close();
      } catch {}

      try {
        if (
          webSocket.readyState ===
          WebSocket.OPEN
        ) {
          webSocket.close(
            code,
            reason,
          );
        }
      } catch {}
    };

  webSocket.addEventListener(
    "message",
    (event) => {
      if (closed) {
        return;
      }

      pendingWrite =
        pendingWrite.then(
          async () => {
            await writer.write(
              await websocketDataToBytes(
                event.data,
              ),
            );
          },
        );

      pendingWrite.catch(
        () => {
          void closeEverything(
            1011,
            "TCP write failed",
            false,
          );
        },
      );
    },
  );

  webSocket.addEventListener(
    "close",
    () => {
      void closeEverything();
    },
  );

  webSocket.addEventListener(
    "error",
    () => {
      void closeEverything(
        1011,
        "WebSocket error",
      );
    },
  );

  try {
    while (!closed) {
      const {
        value,
        done,
      } =
        await reader.read();

      if (
        done ||
        webSocket.readyState !==
          WebSocket.OPEN
      ) {
        break;
      }

      webSocket.send(
        value,
      );
    }

    await closeEverything();
  } catch {
    await closeEverything(
      1011,
      "TCP read failed",
    );
  }
}

async function websocketDataToBytes(
  data,
) {
  if (
    data instanceof
    ArrayBuffer
  ) {
    return new Uint8Array(
      data,
    );
  }

  if (
    ArrayBuffer.isView(
      data,
    )
  ) {
    return new Uint8Array(
      data.buffer,
      data.byteOffset,
      data.byteLength,
    );
  }

  if (
    data instanceof Blob
  ) {
    return new Uint8Array(
      await data.arrayBuffer(),
    );
  }

  if (
    typeof data === "string"
  ) {
    return new TextEncoder()
      .encode(
        data,
      );
  }

  throw new Error(
    "Unsupported WebSocket data type",
  );
}

/* =========================================================
   TCP TEST
   ========================================================= */

async function testTcpConnection(
  hostname,
  port,
  timeoutMs,
) {
  const startedAt =
    Date.now();

  let socket =
    null;

  let timeoutId =
    null;

  try {
    socket =
      connect({
        hostname,
        port,
      });

    const timeout =
      new Promise(
        (
          _,
          reject,
        ) => {
          timeoutId =
            setTimeout(
              () => {
                reject(
                  new Error(
                    `Connection timed out after ${timeoutMs} ms`,
                  ),
                );
              },

              timeoutMs,
            );
        },
      );

    await Promise.race([
      socket.opened,
      timeout,
    ]);

    return {
      ok:
        true,

      elapsedMs:
        Date.now() -
        startedAt,

      error:
        "",
    };
  } catch (error) {
    return {
      ok:
        false,

      elapsedMs:
        Date.now() -
        startedAt,

      error:
        error instanceof Error
          ? error.message
          : String(error),
    };
  } finally {
    if (
      timeoutId !== null
    ) {
      clearTimeout(
        timeoutId,
      );
    }

    if (socket) {
      try {
        await socket.close();
      } catch {}
    }
  }
}

/* =========================================================
   VPS IPv4:PORT PARSER
   ========================================================= */

function parseIPv4Port(
  value,
) {
  if (
    typeof value !== "string"
  ) {
    return null;
  }

  const match =
    value
      .trim()
      .match(
        /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/,
      );

  if (!match) {
    return null;
  }

  const octets =
    match[1]
      .split(".")
      .map(
        Number,
      );

  const port =
    Number(
      match[2],
    );

  if (
    octets.some(
      (number) =>
        !Number.isInteger(
          number,
        ) ||
        number < 0 ||
        number > 255,
    )
  ) {
    return null;
  }

  if (
    !Number.isInteger(
      port,
    ) ||
    port < 1 ||
    port > 65535
  ) {
    return null;
  }

  return {
    hostname:
      octets.join("."),

    port,
  };
}

/* =========================================================
   CLEAN IP / DOMAIN PARSER

   Use:

   104.17.225.144
   104.26.0.176
   example.com

   Port 443 is added automatically.

   Old entries ending in :443 are also accepted.
   ========================================================= */

function parseCleanHost(
  value,
) {
  if (
    typeof value !== "string"
  ) {
    return null;
  }

  let hostname =
    value
      .trim()
      .toLowerCase();

  if (!hostname) {
    return null;
  }

  /*
   * Backward compatibility:
   * host:443 -> host
   */

  const legacyPortMatch =
    hostname.match(
      /^(.+):(\d{1,5})$/,
    );

  if (legacyPortMatch) {
    const port =
      Number(
        legacyPortMatch[2],
      );

    if (port !== 443) {
      return null;
    }

    hostname =
      legacyPortMatch[1];
  }

  if (
    hostname.endsWith(
      ".",
    )
  ) {
    hostname =
      hostname.slice(
        0,
        -1,
      );
  }

  /* IPv4 */

  if (
    /^\d{1,3}(?:\.\d{1,3}){3}$/
      .test(
        hostname,
      )
  ) {
    const octets =
      hostname
        .split(".")
        .map(
          Number,
        );

    if (
      octets.some(
        (number) =>
          !Number.isInteger(
            number,
          ) ||
          number < 0 ||
          number > 255,
      )
    ) {
      return null;
    }

    return octets.join(".");
  }

  /* Domain */

  if (
    hostname.length < 1 ||
    hostname.length > 253
  ) {
    return null;
  }

  const labels =
    hostname.split(
      ".",
    );

  if (
    labels.length < 2
  ) {
    return null;
  }

  const validDomain =
    labels.every(
      (label) =>
        label.length >= 1 &&
        label.length <= 63 &&
        /^[a-z0-9-]+$/
          .test(
            label,
          ) &&
        !label.startsWith(
          "-",
        ) &&
        !label.endsWith(
          "-",
        ),
    );

  if (!validDomain) {
    return null;
  }

  return hostname;
}

function parseCleanHosts(
  input,
) {
  const lines =
    String(
      input ?? "",
    ).split(
      /\r?\n/,
    );

  const values =
    [];

  const seen =
    new Set();

  for (
    let index = 0;
    index < lines.length;
    index += 1
  ) {
    const line =
      lines[
        index
      ].trim();

    if (!line) {
      continue;
    }

    const hostname =
      parseCleanHost(
        line,
      );

    if (!hostname) {
      return {
        ok:
          false,

        values:
          [],

        error:
          `Invalid clean IP/domain on line ${index + 1}: ` +
          `"${line}". Enter only an IPv4 address or domain. ` +
          "Port 443 is added automatically.",
      };
    }

    if (
      seen.has(
        hostname,
      )
    ) {
      continue;
    }

    seen.add(
      hostname,
    );

    values.push(
      hostname,
    );
  }

  return {
    ok:
      true,

    values,

    error:
      "",
  };
}

/* =========================================================
   UUID
   ========================================================= */

function parseUuid(
  value,
) {
  if (
    typeof value !== "string"
  ) {
    return null;
  }

  const uuid =
    value
      .trim()
      .toLowerCase();

  return (
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      .test(
        uuid,
      )
  )
    ? uuid
    : null;
}

/* =========================================================
   SESSION AUTH
   ========================================================= */

async function createSessionToken(
  secret,
) {
  const payload =
    base64UrlEncode(
      new TextEncoder()
        .encode(
          JSON.stringify({
            exp:
              Math.floor(
                Date.now() /
                1000,
              ) +
              SESSION_TTL_SECONDS,

            nonce:
              crypto.randomUUID(),
          }),
        ),
    );

  return (
    `${payload}.` +
    `${
      await signSessionPayload(
        payload,
        secret,
      )
    }`
  );
}

async function isAuthenticated(
  request,
  secret,
) {
  const cookies =
    parseCookies(
      request.headers.get(
        "Cookie",
      ) ?? "",
    );

  const token =
    cookies[
      SESSION_COOKIE
    ];

  if (!token) {
    return false;
  }

  const dot =
    token.lastIndexOf(
      ".",
    );

  if (
    dot < 1
  ) {
    return false;
  }

  const payload =
    token.slice(
      0,
      dot,
    );

  const suppliedSignature =
    token.slice(
      dot + 1,
    );

  const expectedSignature =
    await signSessionPayload(
      payload,
      secret,
    );

  if (
    !(
      await safeEqualStrings(
        suppliedSignature,
        expectedSignature,
      )
    )
  ) {
    return false;
  }

  try {
    const data =
      JSON.parse(
        new TextDecoder()
          .decode(
            base64UrlDecode(
              payload,
            ),
          ),
      );

    return (
      Number.isFinite(
        data.exp,
      ) &&
      data.exp >
        Math.floor(
          Date.now() /
          1000,
        )
    );
  } catch {
    return false;
  }
}

async function signSessionPayload(
  value,
  secret,
) {
  const key =
    await crypto.subtle
      .importKey(
        "raw",

        new TextEncoder()
          .encode(
            secret,
          ),

        {
          name:
            "HMAC",

          hash:
            "SHA-256",
        },

        false,

        [
          "sign",
        ],
      );

  const signature =
    await crypto.subtle
      .sign(
        "HMAC",

        key,

        new TextEncoder()
          .encode(
            value,
          ),
      );

  return base64UrlEncode(
    new Uint8Array(
      signature,
    ),
  );
}

async function safeEqualStrings(
  first,
  second,
) {
  const encoder =
    new TextEncoder();

  const [
    firstHash,
    secondHash,
  ] =
    await Promise.all([
      crypto.subtle.digest(
        "SHA-256",

        encoder.encode(
          first,
        ),
      ),

      crypto.subtle.digest(
        "SHA-256",

        encoder.encode(
          second,
        ),
      ),
    ]);

  const a =
    new Uint8Array(
      firstHash,
    );

  const b =
    new Uint8Array(
      secondHash,
    );

  let difference =
    a.length ^
    b.length;

  const length =
    Math.max(
      a.length,
      b.length,
    );

  for (
    let index = 0;
    index < length;
    index += 1
  ) {
    difference |=
      (
        a[
          index
        ] ?? 0
      ) ^
      (
        b[
          index
        ] ?? 0
      );
  }

  return (
    difference === 0
  );
}

function base64UrlEncode(
  bytes,
) {
  let binary =
    "";

  for (
    const byte of bytes
  ) {
    binary +=
      String.fromCharCode(
        byte,
      );
  }

  return btoa(
    binary,
  )
    .replace(
      /\+/g,
      "-",
    )
    .replace(
      /\//g,
      "_",
    )
    .replace(
      /=+$/g,
      "",
    );
}

function base64UrlDecode(
  value,
) {
  const normalized =
    value
      .replace(
        /-/g,
        "+",
      )
      .replace(
        /_/g,
        "/",
      );

  const padded =
    normalized +
    "=".repeat(
      (
        4 -
        (
          normalized.length %
          4
        )
      ) %
      4,
    );

  const binary =
    atob(
      padded,
    );

  return Uint8Array.from(
    binary,

    (
      character,
    ) =>
      character
        .charCodeAt(
          0,
        ),
  );
}

function parseCookies(
  header,
) {
  const result =
    {};

  for (
    const part of
      header.split(";")
  ) {
    const separator =
      part.indexOf(
        "=",
      );

    if (
      separator <= 0
    ) {
      continue;
    }

    result[
      part
        .slice(
          0,
          separator,
        )
        .trim()
    ] =
      part
        .slice(
          separator + 1,
        )
        .trim();
  }

  return result;
}

function makeSessionCookie(
  value,
  maxAge,
) {
  return (
    `${SESSION_COOKIE}=${value}; ` +
    `Path=${PANEL_PATH}; ` +
    `Max-Age=${maxAge}; ` +
    "HttpOnly; Secure; " +
    "SameSite=Strict"
  );
}

/* =========================================================
   SAME ORIGIN
   ========================================================= */

function isSameOriginRequest(
  request,
) {
  const origin =
    request.headers.get(
      "Origin",
    );

  if (
    !origin ||
    origin === "null"
  ) {
    return true;
  }

  try {
    const originUrl =
      new URL(
        origin,
      );

    const requestUrl =
      new URL(
        request.url,
      );

    const expectedHost = (
      request.headers.get(
        "Host",
      ) ||
      requestUrl.host
    ).toLowerCase();

    return (
      originUrl.host
        .toLowerCase() ===
      expectedHost
    );
  } catch {
    return false;
  }
}

/* =========================================================
   RESPONSES
   ========================================================= */

function redirectResponse(
  location,
  status = 303,
) {
  return new Response(
    null,
    {
      status,

      headers:
        secureHeaders({
          Location:
            location,
        }),
    },
  );
}

function textResponse(
  body,
  status = 200,
) {
  return new Response(
    body,
    {
      status,

      headers:
        secureHeaders({
          "Content-Type":
            "text/plain; charset=UTF-8",
        }),
    },
  );
}

function htmlResponse(
  body,
  status = 200,
) {
  return new Response(
    body,
    {
      status,

      headers:
        secureHeaders({
          "Content-Type":
            "text/html; charset=UTF-8",
        }),
    },
  );
}

function secureHeaders(
  extra = {},
) {
  return {
    "Cache-Control":
      "no-store",

    "Content-Security-Policy":
      "default-src 'none'; " +
      "style-src 'unsafe-inline'; " +
      "script-src 'unsafe-inline' " +
      "https://cdnjs.cloudflare.com; " +
      "img-src data: blob:; " +
      "form-action 'self'; " +
      "base-uri 'none'; " +
      "frame-ancestors 'none'",

    "Referrer-Policy":
      "no-referrer",

    "X-Content-Type-Options":
      "nosniff",

    "X-Frame-Options":
      "DENY",

    ...extra,
  };
}

function escapeHtml(
  value,
) {
  return String(
    value,
  )
    .replaceAll(
      "&",
      "&amp;",
    )
    .replaceAll(
      "<",
      "&lt;",
    )
    .replaceAll(
      ">",
      "&gt;",
    )
    .replaceAll(
      '"',
      "&quot;",
    )
    .replaceAll(
      "'",
      "&#039;",
    );
}

/* =========================================================
   LOGIN PAGE
   ========================================================= */

function renderLoginPage(
  error = "",
) {
  return renderPage(
    "Panel login",

    `
      <main class="card small">

        <div class="eyebrow">
          Cloudflare Worker
        </div>

        <h1>
          Panel login
        </h1>

        <p class="muted">
          Enter the panel password.
        </p>

        ${
          error
            ? `
              <div class="notice error">
                ${escapeHtml(error)}
              </div>
            `
            : ""
        }

        <form
          method="post"
          action="${PANEL_PATH}/login"
        >

          <label>
            Password
          </label>

          <input
            name="password"
            type="password"
            autocomplete="off"
            required
            autofocus
          >

          <button
            type="submit"
          >
            Log in
          </button>

        </form>

      </main>
    `,
  );
}

/* =========================================================
   MAIN PANEL
   ========================================================= */

function renderPanel(
  request,
  target,
  uuid,
  cleanText,
  message = "",
  isError = false,
) {
  const url =
    new URL(
      request.url,
    );

  const clean =
    parseCleanHosts(
      cleanText,
    );

  const count =
    1 +
    (
      clean.ok
        ? clean.values.length
        : 0
    );

  const normalSubscription =
    normalSubscriptionUrl(
      request,
      uuid,
    );

  const pattMciSubscription =
    pattMciSubscriptionUrl(
      request,
      uuid,
    );

  const pattIrancellSubscription =
    pattIrancellSubscriptionUrl(
      request,
      uuid,
    );

  return renderPage(
    "Worker panel",

    `
      <main class="card">

        <div class="top">

          <div>

            <div class="eyebrow">
              Cloudflare Worker
            </div>

            <h1>
              Worker panel
            </h1>

          </div>

          <form
            method="post"
            action="${PANEL_PATH}/logout"
            class="logout"
          >

            <button
              class="secondary"
            >
              Log out
            </button>

          </form>

        </div>

        ${
          message
            ? `
              <div
                class="notice ${
                  isError
                    ? "error"
                    : "success"
                }"
              >
                ${escapeHtml(message)}
              </div>
            `
            : ""
        }

        <form
          method="post"
          action="${PANEL_PATH}/save"
        >

          <label>
            VPS IPv4 address and port
          </label>

          <input
            name="target"
            value="${escapeHtml(target)}"
            placeholder="77.90.6.26:443"
            required
          >

          <div class="hint">
            The real VPS destination
            used by the Worker relay.
          </div>

          <label class="space">
            UUID
          </label>

          <input
            name="uuid"
            value="${escapeHtml(uuid)}"
            placeholder="915ad98f-2a94-4ef6-8f70-cc8cdf37cf15"
            required
          >

          <div class="hint">
            Used inside the VLESS links
            and subscription URLs.
          </div>

          <label class="space">
            Clean IPs / domains
          </label>

          <textarea
            name="clean_ips"
            placeholder="104.17.225.144&#10;104.26.0.176&#10;example.com"
          >${escapeHtml(cleanText)}</textarea>

          <div class="hint">
            One IPv4 address or domain per line.
            Do not add a port. Port 443 is used
            automatically for every entry.
          </div>

          <button
            type="submit"
          >
            Save settings
          </button>

        </form>

        <form
          method="post"
          action="${PANEL_PATH}/test"
          class="test"
        >

          <button
            class="secondary full"
          >
            Test VPS TCP connection
          </button>

        </form>

        <div
          class="stats"
        >

          <div>

            <span>
              Current VPS destination
            </span>

            <strong>
              ${escapeHtml(target)}
            </strong>

          </div>

          <div>

            <span>
              Worker hostname
            </span>

            <strong>
              ${escapeHtml(
                url.hostname,
              )}
            </strong>

          </div>

          <div>

            <span>
              Links in each subscription
            </span>

            <strong>
              ${count}
            </strong>

          </div>

        </div>

        ${renderSubscriptionBlock(
          "Normal subscription link",
          "normal",
          normalSubscription,
        )}

        ${renderSubscriptionBlock(
          "Patt MCI subscription link",
          "patt-mci",
          pattMciSubscription,
        )}

        ${renderSubscriptionBlock(
          "Patt Irancell subscription link",
          "patt-irancell",
          pattIrancellSubscription,
        )}

      </main>

      <script
        src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"
        crossorigin="anonymous"
        referrerpolicy="no-referrer"
      ></script>

      <script>

        function setupCopy(
          buttonId,
          fieldId,
          statusId
        ) {

          const button =
            document.getElementById(
              buttonId
            );

          const field =
            document.getElementById(
              fieldId
            );

          const status =
            document.getElementById(
              statusId
            );

          button.addEventListener(
            "click",

            async () => {

              try {

                await navigator
                  .clipboard
                  .writeText(
                    field.value
                  );

              } catch {

                field.focus();
                field.select();

                document.execCommand(
                  "copy"
                );

              }

              button.textContent =
                "Copied";

              status.textContent =
                "Subscription link copied.";

              setTimeout(
                () => {

                  button.textContent =
                    "Copy";

                  status.textContent =
                    "";

                },

                1600
              );

            }
          );

        }

        function setupQr(
          buttonId,
          fieldId,
          panelId,
          codeId,
          statusId
        ) {

          const button =
            document.getElementById(
              buttonId
            );

          const field =
            document.getElementById(
              fieldId
            );

          const panel =
            document.getElementById(
              panelId
            );

          const code =
            document.getElementById(
              codeId
            );

          const status =
            document.getElementById(
              statusId
            );

          let created =
            false;

          button.addEventListener(
            "click",

            () => {

              const show =
                panel.hidden;

              panel.hidden =
                !show;

              if (
                !show ||
                created
              ) {
                return;
              }

              if (
                typeof QRCode !==
                "function"
              ) {

                status.textContent =
                  "QR library could not be loaded.";

                panel.hidden =
                  true;

                return;

              }

              new QRCode(
                code,

                {
                  text:
                    field.value,

                  width:
                    260,

                  height:
                    260,

                  colorDark:
                    "#000000",

                  colorLight:
                    "#ffffff",

                  correctLevel:
                    QRCode
                      .CorrectLevel
                      .M
                }
              );

              created =
                true;

            }
          );

        }

        [
          "normal",
          "patt-mci",
          "patt-irancell"
        ].forEach(
          (prefix) => {

            setupCopy(
              prefix +
                "-copy",

              prefix +
                "-sub-link",

              prefix +
                "-status"
            );

            setupQr(
              prefix +
                "-qr-button",

              prefix +
                "-sub-link",

              prefix +
                "-qr-panel",

              prefix +
                "-qr-code",

              prefix +
                "-status"
            );

          }
        );

      </script>
    `,
  );
}

/* =========================================================
   SUBSCRIPTION BLOCK
   ========================================================= */

function renderSubscriptionBlock(
  label,
  prefix,
  url,
) {
  return `
    <label
      class="space subscription-title"
    >
      ${escapeHtml(label)}
    </label>

    <div
      class="copyrow"
    >

      <input
        id="${prefix}-sub-link"
        value="${escapeHtml(url)}"
        readonly
      >

      <button
        id="${prefix}-copy"
        type="button"
      >
        Copy
      </button>

      <button
        id="${prefix}-qr-button"
        type="button"
      >
        QR
      </button>

    </div>

    <div
      id="${prefix}-status"
      class="copy-status"
    ></div>

    <div
      id="${prefix}-qr-panel"
      class="qr-panel"
      hidden
    >

      <div
        id="${prefix}-qr-code"
        class="qr-code"
      ></div>

    </div>
  `;
}

/* =========================================================
   PAGE / CSS
   ========================================================= */

function renderPage(
  title,
  body,
) {
  return `<!doctype html>

<html lang="en">

<head>

  <meta charset="utf-8">

  <meta
    name="viewport"
    content="width=device-width, initial-scale=1"
  >

  <title>
    ${escapeHtml(title)}
  </title>

  <style>

    :root {
      color-scheme:
        dark;

      font-family:
        Inter,
        system-ui,
        sans-serif;
    }

    * {
      box-sizing:
        border-box;
    }

    body {
      margin:
        0;

      min-height:
        100vh;

      display:
        grid;

      place-items:
        center;

      padding:
        24px;

      color:
        #f5f7fb;

      background:
        #080b12;
    }

    .card {
      width:
        min(
          100%,
          760px
        );

      padding:
        30px;

      border:
        1px solid
        rgba(
          255,
          255,
          255,
          0.11
        );

      border-radius:
        22px;

      background:
        #111622;

      box-shadow:
        0 24px 80px
        rgba(
          0,
          0,
          0,
          0.45
        );
    }

    .small {
      width:
        min(
          100%,
          430px
        );
    }

    .top {
      display:
        flex;

      justify-content:
        space-between;

      gap:
        20px;
    }

    .eyebrow {
      color:
        #8da9ff;

      font-size:
        0.78rem;

      font-weight:
        800;

      letter-spacing:
        0.13em;

      text-transform:
        uppercase;
    }

    h1 {
      margin:
        4px 0 8px;
    }

    .muted,
    .hint,
    .copy-status,
    .stats span {
      color:
        #aeb7c9;
    }

    form {
      margin-top:
        24px;
    }

    .logout {
      margin:
        0;
    }

    label {
      display:
        block;

      margin-bottom:
        9px;

      font-weight:
        750;
    }

    .space {
      margin-top:
        22px;
    }

    input,
    textarea {
      width:
        100%;

      padding:
        14px 15px;

      border:
        1px solid
        #3a4357;

      border-radius:
        12px;

      background:
        #0c111c;

      color:
        #ffffff;

      font:
        inherit;

      outline:
        none;
    }

    textarea {
      min-height:
        145px;

      resize:
        vertical;

      font-family:
        ui-monospace,
        monospace;
    }

    input:focus,
    textarea:focus {
      border-color:
        #7798ff;

      box-shadow:
        0 0 0 4px
        rgba(
          119,
          152,
          255,
          0.15
        );
    }

    button {
      margin-top:
        18px;

      padding:
        12px 17px;

      border:
        0;

      border-radius:
        11px;

      background:
        #6f91ff;

      color:
        #07101f;

      font:
        inherit;

      font-weight:
        850;

      cursor:
        pointer;
    }

    button:hover {
      filter:
        brightness(
          1.08
        );
    }

    .secondary {
      margin:
        0;

      background:
        #242c3d;

      color:
        #e7ebf4;
    }

    .full {
      width:
        100%;

      padding:
        13px;
    }

    .test {
      margin-top:
        12px;
    }

    .hint {
      margin-top:
        8px;

      font-size:
        0.9rem;
    }

    .notice {
      margin-top:
        18px;

      padding:
        12px 14px;

      border-radius:
        11px;

      font-weight:
        700;
    }

    .success {
      background:
        rgba(
          52,
          211,
          153,
          0.11
        );

      color:
        #a8f3d0;
    }

    .error {
      background:
        rgba(
          248,
          113,
          113,
          0.1
        );

      color:
        #ffc1c1;
    }

    .stats {
      display:
        grid;

      gap:
        12px;

      margin-top:
        26px;
    }

    .stats div {
      display:
        flex;

      justify-content:
        space-between;

      gap:
        18px;

      padding:
        15px;

      border:
        1px solid
        rgba(
          255,
          255,
          255,
          0.09
        );

      border-radius:
        12px;

      background:
        #0d121e;
    }

    .stats strong {
      word-break:
        break-all;

      text-align:
        right;
    }

    .subscription-title {
      margin-top:
        30px;
    }

    .copyrow {
      display:
        grid;

      grid-template-columns:
        minmax(
          0,
          1fr
        )
        auto
        auto;

      gap:
        10px;
    }

    .copyrow button {
      margin:
        0;

      min-width:
        76px;
    }

    .copy-status {
      min-height:
        1.3em;

      margin-top:
        8px;

      font-size:
        0.86rem;
    }

    .qr-panel {
      margin-top:
        14px;

      padding:
        18px;

      border:
        1px solid
        rgba(
          255,
          255,
          255,
          0.1
        );

      border-radius:
        14px;

      background:
        #ffffff;
    }

    .qr-panel[hidden] {
      display:
        none;
    }

    .qr-code {
      display:
        grid;

      place-items:
        center;

      min-height:
        260px;
    }

    .qr-code img,
    .qr-code canvas {
      display:
        block;

      max-width:
        100%;

      height:
        auto;
    }

    @media (
      max-width:
        620px
    ) {

      .card {
        padding:
          22px;
      }

      .top,
      .stats div {
        flex-direction:
          column;
      }

      .stats strong {
        text-align:
          left;
      }

      .copyrow {
        grid-template-columns:
          1fr 1fr;
      }

      .copyrow input {
        grid-column:
          1 / -1;
      }

      .copyrow button {
        width:
          100%;
      }

    }

  </style>

</head>

<body>

  ${body}

</body>

</html>`;
}
