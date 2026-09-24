// Ретранслятор Telegram для net_surgeon.
//
// Там, где провайдер режет IP-адреса Telegram целиком, до его серверов не
// достучаться ни напрямую, ни через web.telegram.org — они на тех же
// адресах. Адреса Cloudflare заблокировать нельзя: на них половина
// интернета. Поэтому net_surgeon открывает WebSocket сюда, а воркер уже из
// сети Cloudflare открывает обычное TCP-соединение к серверу Telegram и
// перекладывает байты в обе стороны.
//
// Воркер видит только зашифрованный поток MTProto: ключи есть лишь у
// приложения Telegram и у сервера, прочитать переписку отсюда нельзя.
//
// Соединяется ТОЛЬКО с адресами Telegram. Воркер, который идёт куда
// попросят, — это открытый прокси на вашем аккаунте для любого, кто узнает
// его адрес.
//
//   GET /apiws?dst=149.154.167.51&port=443   (Upgrade: websocket)

import { connect } from "cloudflare:sockets";

// Сети Telegram (AS62041, AS59930, AS62014, AS211157).
const TELEGRAM_V4 = [
  ["149.154.160.0", 20],
  ["91.108.4.0", 22],
  ["91.108.8.0", 22],
  ["91.108.12.0", 22],
  ["91.108.16.0", 22],
  ["91.108.20.0", 22],
  ["91.108.56.0", 22],
  ["91.105.192.0", 23],
  ["95.161.64.0", 20],
  ["185.76.151.0", 24],
];

const PORTS = new Set(["443", "80", "5222"]);

function ipv4ToInt(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function isTelegram(ip) {
  const n = ipv4ToInt(ip);
  if (n === null) return false;
  return TELEGRAM_V4.some(([base, bits]) => {
    const size = 2 ** (32 - bits);
    const start = ipv4ToInt(base);
    return n >= start && n < start + size;
  });
}

async function toBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data && typeof data.arrayBuffer === "function") {
    return new Uint8Array(await data.arrayBuffer());
  }
  return new Uint8Array();
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== "/apiws") {
      return new Response("net_surgeon relay\n", { status: 404 });
    }
    if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
      return new Response("Expected websocket\n", { status: 426 });
    }

    const dst = url.searchParams.get("dst") || "";
    const port = url.searchParams.get("port") || "443";
    if (!isTelegram(dst) || !PORTS.has(port)) {
      return new Response("Only Telegram addresses\n", { status: 403 });
    }

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    server.accept();

    const socket = connect({ hostname: dst, port: Number(port) });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    const closeAll = (code, reason) => {
      try { server.close(code, reason); } catch {}
      try { socket.close(); } catch {}
    };

    // Сообщения пишутся строго по очереди: при параллельной записи куски
    // потока могли бы перемешаться, а MTProto порядок байт не прощает.
    let queue = Promise.resolve();
    server.addEventListener("message", (event) => {
      queue = queue.then(async () => {
        try {
          await writer.write(await toBytes(event.data));
        } catch {
          closeAll(1011, "tcp write failed");
        }
      });
    });
    server.addEventListener("close", () => closeAll(1000, "client closed"));
    server.addEventListener("error", () => closeAll(1011, "client error"));

    (async () => {
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value) server.send(value);
        }
      } catch {
      } finally {
        closeAll(1000, "upstream closed");
      }
    })();

    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { "Sec-WebSocket-Protocol": "binary" },
    });
  },
};
