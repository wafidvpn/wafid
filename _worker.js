import { connect } from "cloudflare:sockets";

// ====== CONFIG (ubah sesuai kebutuhan atau set via env) ======
const ROOT_DOMAIN = "wafidvpn.workers.dev";
let serviceName = "wafid04"; // akan di-overwrite berdasarkan hostname
let APP_DOMAIN = "wafid04.wafidvpn.workers.dev"; // default

// Jika ingin gunakan Cloudflare API fitur domain management, set ENV variables pada Worker
// API_KEY -> Global API Key / Token, API_EMAIL -> account email, ACCOUNT_ID, ZONE_ID
const apiKey = ""; // optional
const apiEmail = ""; // optional
const accountID = ""; // optional
const zoneID = ""; // optional

// ====== RUNTIME VARIABLES ======
let proxyIP = "";
let cachedProxyList = [];

// ====== CONSTANTS ======
const horse = "dHJvamFu"; // base64 'trojan'
const flash = "dm1lc3M="; // base64 'vmess'
const v2 = "djJyYXk="; // base64 'v2ray'
const neko = "Y2xhc2g="; // base64 'clash'

const PORTS = [443, 80];
const PROTOCOLS = [atob(horse), atob(flash), "ss"];
const SUB_PAGE_URL = "https://foolvpn.me/nautica";
const KV_PROXY_URL = "https://raw.githubusercontent.com/wafidvpn/wafid/refs/heads/main/kvProxyList.json";
const PROXY_BANK_URL = "https://raw.githubusercontent.com/DarkFacebookNet378/Rahasia/refs/heads/main/naoncing-v2-sg-id.txt";
const DNS_SERVER_ADDRESS = "1.1.1.1";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = {
  host: "udp-relay.hobihaus.space",
  port: 7300,
};
const PROXY_HEALTH_CHECK_API = "https://id1.foolvpn.me/api/v1/check";
const CONVERTER_URL = "https://api.foolvpn.me/convert";
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

// ====== HELPERS ======
function shuffleArray(array) {
  let currentIndex = array.length;
  while (currentIndex != 0) {
    let randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;
    [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function reverse(s) {
  return s.split("").reverse().join("");
}

function getFlagEmoji(isoCode) {
  if (!isoCode) return "";
  try {
    const codePoints = isoCode
      .toUpperCase()
      .split("")
      .map((char) => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  } catch (e) {
    return "";
  }
}

async function getKVProxyList(kvProxyUrl = KV_PROXY_URL) {
  if (!kvProxyUrl) throw new Error("No KV Proxy URL Provided!");
  const kvProxy = await fetch(kvProxyUrl);
  if (kvProxy.status == 200) return await kvProxy.json();
  return {};
}

async function getProxyList(proxyBankUrl = PROXY_BANK_URL) {
  if (!proxyBankUrl) throw new Error("No Proxy Bank URL Provided!");
  const proxyBank = await fetch(proxyBankUrl);
  if (proxyBank.status == 200) {
    const text = (await proxyBank.text()) || "";
    const proxyString = text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));

    cachedProxyList = proxyString
      .map((entry) => {
        const [proxyIP, proxyPort, country, org] = entry.split(",");
        return {
          proxyIP: proxyIP || "Unknown",
          proxyPort: proxyPort || "Unknown",
          country: country || "Unknown",
          org: org || "Unknown Org",
        };
      })
      .filter(Boolean);
  }
  return cachedProxyList;
}

async function reverseWeb(request, target, targetPath) {
  const targetUrl = new URL(request.url);
  const targetChunk = target.split(":");

  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk[1]?.toString() || "443";
  targetUrl.pathname = targetPath || targetUrl.pathname;

  const modifiedRequest = new Request(targetUrl, request);
  modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

  const response = await fetch(modifiedRequest);

  const newResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) newResponse.headers.set(key, value);
  newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");

  return newResponse;
}

// ====== HTML PAGE BUILDER (sederhana, cukup untuk /sub) ======
function buildSubHtml({ title, proxyList = [], page = 0, perPage = 24, service }) {
  const start = page * perPage;
  const end = Math.min(start + perPage, proxyList.length);
  const items = proxyList.slice(start, end);

  const cards = items
    .map((p, idx) => {
      const index = start + idx + 1;
      const uriBase = `${atob(horse)}://${APP_DOMAIN}`;
      // build sample ws uri as string (no real encoding here)
      const path = `/${p.proxyIP}-${p.proxyPort}`;
      const tls = p.proxyPort == 443 ? "TLS" : "NTLS";
      return `
      <div class="max-w-xs p-3 border rounded-lg">
        <div class="font-semibold">${index}. ${getFlagEmoji(p.country)} ${p.org}</div>
        <div class="text-sm">${p.proxyIP}:${p.proxyPort} — WS ${tls}</div>
        <div class="mt-2 break-words text-xs text-blue-700">${uriBase}${path}#${service}</div>
      </div>`;
    })
    .join("\n");

  const pageButtons = `
    <a href="/sub/0" style="margin-right:8px">First</a>
    <a href="/sub/${Math.max(0, page - 1)}" style="margin-right:8px">Prev</a>
    <a href="/sub/${page + 1}" style="margin-right:8px">Next</a>
  `;

  return `<!doctype html>
  <html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>${title}</title>
    <style>body{font-family:Inter,system-ui,Segoe UI,Roboto,Helvetica,Arial;margin:0;padding:16px;background:#fff;color:#111} .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}</style>
  </head>
  <body>
    <h1>${title}</h1>
    <div>Total: ${proxyList.length}</div>
    <div class="grid">${cards}</div>
    <div style="margin-top:12px">${pageButtons}</div>
  </body>
  </html>`;
}

// ====== CLOUDFlare API (opsional, adaptasi dari worker lama) ======
class CloudflareApi {
  constructor(bearer = apiKey, email = apiEmail, account = accountID, zone = zoneID) {
    this.bearer = `Bearer ${bearer}`;
    this.accountID = account;
    this.zoneID = zone;
    this.apiEmail = email;
    this.apiKey = bearer;

    this.headers = {
      Authorization: this.bearer,
      "X-Auth-Email": this.apiEmail,
      "X-Auth-Key": this.apiKey,
      "Content-Type": "application/json",
    };
  }

  async getDomainList() {
    if (!this.accountID) return [];
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, { headers: { ...this.headers } });
    if (res.status == 200) {
      const respJson = await res.json();
      return respJson.result.filter((d) => d.service == serviceName).map((d) => d.hostname);
    }
    return [];
  }

  async registerDomain(domain) {
    if (!this.accountID || !this.zoneID) return 400;
    domain = domain.toLowerCase();
    const registered = await this.getDomainList();
    if (!domain.endsWith(ROOT_DOMAIN)) return 400;
    if (registered.includes(domain)) return 409;

    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      method: "PUT",
      body: JSON.stringify({ environment: "production", hostname: domain, service: serviceName, zone_id: this.zoneID }),
      headers: { ...this.headers },
    });
    return res.status;
  }
}

// ====== FETCH HANDLER ======
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      APP_DOMAIN = url.hostname;
      serviceName = APP_DOMAIN.split(".")[0] || serviceName;

      const upgradeHeader = request.headers.get("Upgrade");

      // Websocket handling (core dari worker baru)
      if (upgradeHeader === "websocket") {
        const proxyMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        if (url.pathname.length == 3 || url.pathname.match(",")) {
          const proxyKeys = url.pathname.replace("/", "").toUpperCase().split(",");
          const proxyKey = proxyKeys[Math.floor(Math.random() * proxyKeys.length)];
          const kvProxy = await getKVProxyList();
          proxyIP = kvProxy[proxyKey][Math.floor(Math.random() * kvProxy[proxyKey].length)];
          return await websocketHandler(request);
        } else if (proxyMatch) {
          proxyIP = proxyMatch[1];
          return await websocketHandler(request);
        }
      }

      // Health check endpoint (dari worker lama)
      if (url.pathname.startsWith("/foolvpn-health-check")) {
        const pathMatch = url.pathname.match(/\/(\d+\.\d+\.\d+\.\d+)-(\d+)/);
        if (pathMatch) {
          const proxyIPc = pathMatch[1];
          const proxyPort = pathMatch[2];
          try {
            const foolResponse = await fetch(`${PROXY_HEALTH_CHECK_API}?ip=${proxyIPc}:${proxyPort}`);
            const foolData = await foolResponse.json();
            return new Response(JSON.stringify(foolData), { status: foolResponse.status, headers: { ...CORS_HEADER_OPTIONS, "Content-Type": "application/json" } });
          } catch (error) {
            return new Response(JSON.stringify({ proxyip: false, error: error.message }), { status: 500, headers: { ...CORS_HEADER_OPTIONS, "Content-Type": "application/json" } });
          }
        }
        return new Response(JSON.stringify({ proxyip: false, error: "Invalid path format. Use: /foolvpn-health-check/IP-PORT" }), { status: 400, headers: { ...CORS_HEADER_OPTIONS, "Content-Type": "application/json" } });
      }

      // /sub simple HTML view (mimic worker_lama generator but simpler)
      if (url.pathname.startsWith("/sub")) {
        const page = url.pathname.match(/^\/sub\/(\d+)$/);
        const pageIndex = parseInt(page ? page[1] : "0");
        const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL || PROXY_BANK_URL;

        let proxyList = await getProxyList(proxyBankUrl);

        // optional filter by cc
        const countrySelect = url.searchParams.get("cc")?.split(",");
        if (countrySelect && countrySelect.length) {
          proxyList = proxyList.filter((p) => countrySelect.includes(p.country));
        }

        const html = buildSubHtml({ title: `Proxy list - ${serviceName}`, proxyList, page: pageIndex, perPage: 24, service: serviceName });
        return new Response(html, { status: 200, headers: { "Content-Type": "text/html;charset=utf-8" } });
      }

      // /check
      if (url.pathname.startsWith("/check")) {
        const target = url.searchParams.get("target").split(":");
        const result = await checkProxyHealth(target[0], target[1] || "443");
        return new Response(JSON.stringify(result), { status: 200, headers: { ...CORS_HEADER_OPTIONS, "Content-Type": "application/json" } });
      }

      // API v1 (sub generator + myip + domains)
      if (url.pathname.startsWith("/api/v1")) {
        const apiPath = url.pathname.replace("/api/v1", "");

        if (apiPath.startsWith("/sub")) {
          const filterCC = url.searchParams.get("cc")?.split(",") || [];
          const filterPort = url.searchParams.get("port")?.split(",") || PORTS;
          const filterVPN = url.searchParams.get("vpn")?.split(",") || PROTOCOLS;
          const filterLimit = parseInt(url.searchParams.get("limit")) || 10;
          const filterFormat = url.searchParams.get("format") || "raw";
          const fillerDomain = url.searchParams.get("domain") || APP_DOMAIN;

          const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL || PROXY_BANK_URL;
          const proxyList = await getProxyList(proxyBankUrl)
            .then((proxies) => {
              if (filterCC.length) return proxies.filter((proxy) => filterCC.includes(proxy.country));
              return proxies;
            })
            .then((proxies) => {
              shuffleArray(proxies);
              return proxies;
            });

          const uuid = crypto.randomUUID();
          const result = [];
          for (const proxy of proxyList) {
            const uri = new URL(`${atob(horse)}://${fillerDomain}`);
            uri.searchParams.set("encryption", "none");
            uri.searchParams.set("type", "ws");
            uri.searchParams.set("host", APP_DOMAIN);

            for (const port of filterPort) {
              for (const protocol of filterVPN) {
                if (result.length >= filterLimit) break;
                uri.protocol = protocol;
                uri.port = port.toString();
                if (protocol == "ss") {
                  uri.username = btoa(`none:${uuid}`);
                  uri.searchParams.set(
                    "plugin",
                    `${atob(v2)}-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${proxy.proxyIP}-${proxy.proxyPort};host=${APP_DOMAIN}`
                  );
                } else {
                  uri.username = uuid;
                }

                uri.searchParams.set("security", port == 443 ? "tls" : "none");
                uri.searchParams.set("sni", port == 80 && protocol == atob(flash) ? "" : APP_DOMAIN);
                uri.searchParams.set("path", `/${proxy.proxyIP}-${proxy.proxyPort}`);

                uri.hash = `${result.length + 1} ${getFlagEmoji(proxy.country)} ${proxy.org} WS ${port == 443 ? "TLS" : "NTLS"} [${serviceName}]`;
                result.push(uri.toString());
              }
            }
          }

          let finalResult = "";
          switch (filterFormat) {
            case "raw":
              finalResult = result.join("\n");
              break;
            case atob(v2):
              finalResult = btoa(result.join("\n"));
              break;
            case atob(neko):
            case "sfa":
            case "bfr":
              const res = await fetch(CONVERTER_URL, {
                method: "POST",
                body: JSON.stringify({ url: result.join(","), format: filterFormat, template: "cf" }),
              });
              if (res.status == 200) finalResult = await res.text();
              else return new Response(res.statusText, { status: res.status, headers: { ...CORS_HEADER_OPTIONS } });
              break;
          }

          return new Response(finalResult, { status: 200, headers: { ...CORS_HEADER_OPTIONS } });
        } else if (apiPath.startsWith("/myip")) {
          return new Response(JSON.stringify({ ip: request.headers.get("cf-connecting-ipv6") || request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip"), colo: request.headers.get("cf-ray")?.split("-")[1], ...request.cf }), { headers: { ...CORS_HEADER_OPTIONS } });
        } else if (apiPath.startsWith("/domains")) {
          if (!apiKey || !apiEmail || !accountID || !zoneID) return new Response("Api not ready", { status: 500 });

          const wildcardApiPath = apiPath.replace("/domains", "");
          const cloudflareApi = new CloudflareApi(apiKey, apiEmail, accountID, zoneID);

          if (wildcardApiPath == "/get") {
            const domains = await cloudflareApi.getDomainList();
            return new Response(JSON.stringify(domains), { headers: { ...CORS_HEADER_OPTIONS } });
          } else if (wildcardApiPath == "/put") {
            const domain = url.searchParams.get("domain");
            const register = await cloudflareApi.registerDomain(domain);
            return new Response(register.toString(), { status: register, headers: { ...CORS_HEADER_OPTIONS } });
          }
        }
      }

      // default reverse proxy
      const targetReversePrx = env.REVERSE_PRX_TARGET || "example.com";
      return await reverseWeb(request, targetReversePrx);
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, { status: 500, headers: { ...CORS_HEADER_OPTIONS } });
    }
  },
};

// ====== WEBSOCKET / STREAM HANDLERS (from worker baru, preserved) ======
async function websocketHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = { value: null };
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS) {
            return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log, RELAY_SERVER_UDP);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const protocol = await protocolSniffer(chunk);
          let protocolHeader;

          if (protocol === atob(horse)) {
            protocolHeader = readHorseHeader(chunk);
          } else if (protocol === atob(flash)) {
            protocolHeader = readFlashHeader(chunk);
          } else if (protocol === "ss") {
            protocolHeader = readSsHeader(chunk);
          } else {
            throw new Error("Unknown Protocol!");
          }

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

          if (protocolHeader.hasError) throw new Error(protocolHeader.message);

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
              return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, protocolHeader.version, log, RELAY_SERVER_UDP);
            }
            return handleUDPOutbound(protocolHeader.addressRemote, protocolHeader.portRemote, chunk, webSocket, protocolHeader.version, log, RELAY_SERVER_UDP);
          }

          handleTCPOutBound(remoteSocketWrapper, protocolHeader.addressRemote, protocolHeader.portRemote, protocolHeader.rawClientData, webSocket, protocolHeader.version, log);
        },
        close() { log(`readableWebSocketStream is close`); },
        abort(reason) { log(`readableWebSocketStream is abort`, JSON.stringify(reason)); },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, { status: 101, webSocket: client });
}

async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) {
      if (horseDelimiter[2] === 0x01 || horseDelimiter[2] === 0x03 || horseDelimiter[2] === 0x7f) {
        if (horseDelimiter[3] === 0x01 || horseDelimiter[3] === 0x03 || horseDelimiter[3] === 0x04) {
          return atob(horse);
        }
      }
    }
  }

  const flashDelimiter = new Uint8Array(buffer.slice(1, 17));
  if (arrayBufferToHex(flashDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
    return atob(flash);
  }

  return "ss";
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port: port });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = await connectAndWrite(proxyIP.split(/[:=-]/)[0] || addressRemote, proxyIP.split(/[:=-]/)[1] || portRemote);
    tcpSocket.closed.catch((error) => { console.log("retry tcpSocket closed error", error); }).finally(() => { safeCloseWebSocket(webSocket); });
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

async function handleUDPOutbound(targetAddress, targetPort, dataChunk, webSocket, responseHeader, log, relay) {
  try {
    let protocolHeader = responseHeader;
    const tcpSocket = connect({ hostname: relay.host, port: relay.port });

    const header = `udp:${targetAddress}:${targetPort}`;
    const headerBuffer = new TextEncoder().encode(header);
    const separator = new Uint8Array([0x7c]);
    const relayMessage = new Uint8Array(headerBuffer.length + separator.length + dataChunk.byteLength);
    relayMessage.set(headerBuffer, 0);
    relayMessage.set(separator, headerBuffer.length);
    relayMessage.set(new Uint8Array(dataChunk), headerBuffer.length + separator.length);

    const writer = tcpSocket.writable.getWriter();
    await writer.write(relayMessage);
    writer.releaseLock();

    await tcpSocket.readable.pipeTo(new WritableStream({
      async write(chunk) {
        if (webSocket.readyState === WS_READY_STATE_OPEN) {
          if (protocolHeader) { webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer()); protocolHeader = null; }
          else { webSocket.send(chunk); }
        }
      },
      close() { log(`UDP connection to ${targetAddress} closed`); },
      abort(reason) { console.error(`UDP connection aborted due to ${reason}`); },
    }));
  } catch (e) { console.error(`Error while handling UDP outbound: ${e.message}`); }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => { if (readableStreamCancel) return; controller.enqueue(event.data); });
      webSocketServer.addEventListener("close", () => { safeCloseWebSocket(webSocketServer); if (readableStreamCancel) return; controller.close(); });
      webSocketServer.addEventListener("error", (err) => { log("webSocketServer has error"); controller.error(err); });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error); else if (earlyData) controller.enqueue(earlyData);
    },
    pull(controller) {},
    cancel(reason) { if (readableStreamCancel) return; log(`ReadableStream was canceled, due to ${reason}`); readableStreamCancel = true; safeCloseWebSocket(webSocketServer); },
  });
  return stream;
}

function readSsHeader(ssBuffer) {
  const view = new DataView(ssBuffer);
  const addressType = view.getUint8(0);
  let addressLength = 0; let addressValueIndex = 1; let addressValue = "";
  switch (addressType) {
    case 1: addressLength = 4; addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
    case 3: addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0]; addressValueIndex += 1; addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
    case 4: addressLength = 16; const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i*2).toString(16)); addressValue = ipv6.join(":"); break;
    default: return { hasError: true, message: `Invalid addressType for SS: ${addressType}` };
  }
  if (!addressValue) return { hasError: true, message: `Destination address empty, address type is: ${addressType}` };
  const portIndex = addressValueIndex + addressLength; const portBuffer = ssBuffer.slice(portIndex, portIndex + 2); const portRemote = new DataView(portBuffer).getUint16(0);
  return { hasError: false, addressRemote: addressValue, addressType, portRemote, rawDataIndex: portIndex+2, rawClientData: ssBuffer.slice(portIndex+2), version: null, isUDP: portRemote==53 };
}

function readFlashHeader(buffer) {
  const version = new Uint8Array(buffer.slice(0,1)); let isUDP = false; const optLength = new Uint8Array(buffer.slice(17,18))[0]; const cmd = new Uint8Array(buffer.slice(18+optLength,18+optLength+1))[0]; if (cmd===1) {} else if (cmd===2) isUDP=true; else return { hasError:true, message:`command ${cmd} is not supported` };
  const portIndex = 18 + optLength + 1; const portBuffer = buffer.slice(portIndex, portIndex+2); const portRemote = new DataView(portBuffer).getUint16(0);
  let addressIndex = portIndex + 2; const addressBuffer = new Uint8Array(buffer.slice(addressIndex,addressIndex+1)); const addressType = addressBuffer[0]; let addressLength=0; let addressValueIndex=addressIndex+1; let addressValue="";
  switch(addressType){ case 1: addressLength=4; addressValue=new Uint8Array(buffer.slice(addressValueIndex,addressValueIndex+addressLength)).join('.'); break; case 2: addressLength=new Uint8Array(buffer.slice(addressValueIndex,addressValueIndex+1))[0]; addressValueIndex+=1; addressValue=new TextDecoder().decode(buffer.slice(addressValueIndex,addressValueIndex+addressLength)); break; case 3: addressLength=16; const dv=new DataView(buffer.slice(addressValueIndex,addressValueIndex+addressLength)); const ipv6=[]; for(let i=0;i<8;i++) ipv6.push(dv.getUint16(i*2).toString(16)); addressValue=ipv6.join(':'); break; default: return { hasError:true, message:`invild  addressType is ${addressType}` } }
  if(!addressValue) return { hasError:true, message:`addressValue is empty, addressType is ${addressType}` };
  return { hasError:false, addressRemote:addressValue, addressType, portRemote, rawDataIndex:addressValueIndex+addressLength, rawClientData:buffer.slice(addressValueIndex+addressLength), version:new Uint8Array([version[0],0]), isUDP };
}

function readHorseHeader(buffer){
  const dataBuffer = buffer.slice(58);
  if (dataBuffer.byteLength < 6) return { hasError:true, message: "invalid request data" };
  let isUDP=false; const view=new DataView(dataBuffer); const cmd=view.getUint8(0); if (cmd==3) isUDP=true; else if (cmd!=1) throw new Error("Unsupported command type!");
  let addressType=view.getUint8(1); let addressLength=0; let addressValueIndex=2; let addressValue="";
  switch(addressType){ case 1: addressLength=4; addressValue=new Uint8Array(dataBuffer.slice(addressValueIndex,addressValueIndex+addressLength)).join('.'); break; case 3: addressLength=new Uint8Array(dataBuffer.slice(addressValueIndex,addressValueIndex+1))[0]; addressValueIndex+=1; addressValue=new TextDecoder().decode(dataBuffer.slice(addressValueIndex,addressValueIndex+addressLength)); break; case 4: addressLength=16; const dv=new DataView(dataBuffer.slice(addressValueIndex,addressValueIndex+addressLength)); const ipv6=[]; for(let i=0;i<8;i++) ipv6.push(dv.getUint16(i*2).toString(16)); addressValue=ipv6.join(':'); break; default: return { hasError:true, message:`invalid addressType is ${addressType}` } }
  if(!addressValue) return { hasError:true, message:`address is empty, addressType is ${addressType}` };
  const portIndex=addressValueIndex+addressLength; const portBuffer=dataBuffer.slice(portIndex, portIndex+2); const portRemote=new DataView(portBuffer).getUint16(0);
  return { hasError:false, addressRemote:addressValue, addressType, portRemote, rawDataIndex: portIndex+4, rawClientData: dataBuffer.slice(portIndex+4), version: null, isUDP };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log){
  let header = responseHeader; let hasIncomingData=false;
  await remoteSocket.readable.pipeTo(new WritableStream({ start(){}, async write(chunk, controller){ hasIncomingData=true; if (webSocket.readyState!==WS_READY_STATE_OPEN) controller.error("webSocket.readyState is not open, maybe close"); if (header){ webSocket.send(await new Blob([header, chunk]).arrayBuffer()); header=null; } else { webSocket.send(chunk); } }, close(){ log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`); }, abort(reason){ console.error(`remoteConnection!.readable abort`, reason); } })).catch((error)=>{ console.error(`remoteSocketToWS has exception `, error.stack||error); safeCloseWebSocket(webSocket); });
  if (hasIncomingData===false && retry) { log(`retry`); retry(); }
}

function safeCloseWebSocket(socket){ try{ if (socket.readyState===WS_READY_STATE_OPEN || socket.readyState===WS_READY_STATE_CLOSING) socket.close(); } catch(e){ console.error("safeCloseWebSocket error", e); } }

async function checkProxyHealth(proxyIPc, proxyPort){ const req = await fetch(`${PROXY_HEALTH_CHECK_API}?ip=${proxyIPc}:${proxyPort}`); return await req.json(); }

function base64ToArrayBuffer(base64Str){ if (!base64Str) return { error: null }; try{ base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/"); const decode = atob(base64Str); const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0)); return { earlyData: arryBuffer.buffer, error: null }; } catch(error){ return { error }; } }

// End of file
