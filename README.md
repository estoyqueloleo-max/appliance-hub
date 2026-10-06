# 🛡️ Appliance Cloud Hub (`web.appliance.klitosan.com`)

Panel Central de Control y Aprovisionamiento para Appliances Pingo / EstoyQueLoLeo, con soporte multitenant DDNS, ECH (Encrypted Client Hello), Cloudflare Access y notificaciones push transversales.

## 🚀 Despliegue en Cloudflare Workers

```bash
npm install
npm run build
npx wrangler deploy
```

## 🔐 Configuración de Seguridad en Cloudflare Access (Zero Trust)

1. En el panel de Cloudflare: **Zero Trust ➔ Access ➔ Applications ➔ Add Application**.
2. **Type:** Self-hosted.
3. **Application Domain:** `web.appliance.klitosan.com`.
4. **Policy:** Allow ➔ Email: `josejuan.montiel@gmail.com` (Vía Google o One-Time PIN).

El Worker valida automáticamente la cabecera inyectada por Cloudflare:
`Cf-Access-Authenticated-User-Email: josejuan.montiel@gmail.com`.

## 📦 Características del Hub

* **Dashboard Web Centralizado:** Servido en la raíz (`/`) con autenticación Zero Trust.
* **Aprovisionamiento de Appliances:** Generación directa de drop-ins `ddns.txt` y resolución de subdominios (`<id>.appliances.klitosan.com`).
* **OAuth 2.0 Device Flow (RFC 8628):** Activación web interactiva para terminales en `/ddns/activate`.
* **DDNS con Protección de Cuota (Zero-API Cost):** Heartbeats periódicos (`/api/v1/ddns/heartbeat`) sin llamadas a la API de Cloudflare si la IP no cambia.
* **Emisión de WebPush:** Notificaciones push transversales a nodos y suscriptores.
