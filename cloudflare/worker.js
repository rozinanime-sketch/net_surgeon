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
// Если задан секрет (`npx wrangler secret put RELAY_TOKEN`), без него воркер
// не отвечает: адрес *.workers.dev находится по журналам сертификатов, и
// чужие соединения выбирали бы дневной лимит бесплатного тарифа.
//
//   GET /apiws?dst=149.154.167.51&port=443   (Upgrade: websocket)
//   X-Relay-Token: <секрет>                   (если он задан)

import { connect } from "cloudflare:sockets";

// Сети Telegram (AS62041, AS59930, AS62014, AS211157). Тот же список — в
// src/proxy/telegram.rs (TELEGRAM_V4); тест там сверяет их.
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

// Сколько ждать TCP до Telegram, прежде чем ответить клиенту отказом.
const CONNECT_TIMEOUT_MS = 10_000;

// Предел данных от клиента, ещё не записанных в TCP. У WebSocket в Workers
// нет управления потоком: приём сообщений не приостановить, и при отправке
// быстрее, чем уходит в Telegram, буфер рос до лимита памяти isolate
// (128 МБ) — тогда рвались все соединения в нём. Лучше закрыть одно.
const MAX_PENDING_BYTES = 16 * 1024 * 1024;

// Только десятичные октеты без ведущих нулей: «056» одни разборщики читают
// как 56, другие — как восьмеричное 46, и проверка сети с подключением
// разошлись бы.
function ipv4ToInt(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function intToIpv4(n) {
  return [24, 16, 8, 0].map((shift) => Math.floor(n / 2 ** shift) % 256).join(".");
}

function isTelegram(n) {
  return TELEGRAM_V4.some(([base, bits]) => {
    const size = 2 ** (32 - bits);
    const start = ipv4ToInt(base);
    return n >= start && n < start + size;
  });
}

async function toBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data && typeof data.arrayBuffer === "function") {
    return new Uint8Array(await data.arrayBuffer());
  }
  // Молча подставить пустой массив значило бы испортить поток MTProto.
  throw new TypeError("unsupported message type");
}

// Сравнение секрета за постоянное время.
function tokenMatches(given, expected) {
  const a = new TextEncoder().encode(given);
  const b = new TextEncoder().encode(expected);
  if (a.byteLength !== b.byteLength) return false;
  return crypto.subtle.timingSafeEqual(a, b);
}

function timeout(ms) {
  return new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/apiws") {
      return new Response("net_surgeon relay\n", { status: 404 });
    }
    // Секрет — до всего остального: без него воркер не подтверждает даже,
    // что это ретранслятор.
    if (env.RELAY_TOKEN && !tokenMatches(request.headers.get("X-Relay-Token") || "", env.RELAY_TOKEN)) {
      return new Response("net_surgeon relay\n", { status: 404 });
    }
    if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
      return new Response("Expected websocket\n", { status: 426 });
    }

    const ip = ipv4ToInt(url.searchParams.get("dst") || "");
    const port = url.searchParams.get("port") || "443";
    if (ip === null || !isTelegram(ip) || !PORTS.has(port)) {
      return new Response("Only Telegram addresses\n", { status: 403 });
    }

    // Подключаемся к адресу, собранному из проверенного числа, а не к
    // строке из запроса.
    const socket = connect({ hostname: intToIpv4(ip), port: Number(port) });

    // Когда Telegram или сеть рвут соединение, эти промисы отклоняются.
    // Без обработчика это «необработанное исключение» воркера, хотя для
    // ретранслятора обрыв — обычное дело: закрытие ловится ниже.
    const ignore = () => {};
    socket.closed.catch(ignore);

    // 101 — только когда TCP до Telegram открыт. Иначе клиент видел бы
    // успешное подключение, сразу закрытое, и не мог отличить его от
    // штатного конца.
    try {
      await Promise.race([socket.opened, timeout(CONNECT_TIMEOUT_MS)]);
    } catch {
      try { socket.close().catch(ignore); } catch {}
      return new Response("Telegram unreachable\n", { status: 502 });
    }

    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    writer.closed.catch(ignore);
    reader.closed.catch(ignore);

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    server.accept();

    let closed = false;
    const closeAll = (code, reason) => {
      if (closed) return;
      closed = true;
      try { server.close(code, reason); } catch {}
      // close() возвращает промис: try/catch его отказ не ловит.
      try { socket.close().catch(ignore); } catch {}
    };

    // Сообщения пишутся строго по очереди: при параллельной записи куски
    // потока могли бы перемешаться, а MTProto порядок байт не прощает.
    let queue = Promise.resolve();
    let pending = 0;
    server.addEventListener("message", (event) => {
      if (closed) return;
      const size = typeof event.data === "string" ? event.data.length : event.data.byteLength || 0;
      pending += size;
      if (pending > MAX_PENDING_BYTES) {
        closeAll(1011, "client faster than upstream");
        return;
      }
      queue = queue.then(async () => {
        if (closed) return;
        try {
          await writer.write(await toBytes(event.data));
        } catch (e) {
          closeAll(e instanceof TypeError ? 1003 : 1011, "tcp write failed");
        } finally {
          pending -= size;
        }
      });
    });
    // Клиент закрыл — сначала дописать то, что он успел прислать: иначе
    // последний запрос MTProto терялся бы в очереди.
    server.addEventListener("close", () => {
      queue.finally(() => closeAll(1000, "client closed"));
    });
    server.addEventListener("error", () => closeAll(1011, "client error"));

    (async () => {
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value) server.send(value);
        }
        closeAll(1000, "upstream closed");
      } catch {
        // Обрыв со стороны Telegram — не штатный конец.
        closeAll(1011, "upstream failed");
      }
    })();

    // Подпротокол — только если клиент его просил (RFC 6455).
    const offered = (request.headers.get("Sec-WebSocket-Protocol") || "")
      .split(",")
      .map((p) => p.trim());
    const headers = offered.includes("binary") ? { "Sec-WebSocket-Protocol": "binary" } : {};
    return new Response(null, { status: 101, webSocket: client, headers });
  },
};
