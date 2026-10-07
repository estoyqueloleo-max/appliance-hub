package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/rs/cors"
	"github.com/syumai/workers"
	"github.com/syumai/workers/cloudflare"
	"github.com/syumai/workers/cloudflare/kv"
)

const (
	kvNamespace     = "APPLIANCE_HUB_KV"
	vapidPublicKey  = "BEJ45uzzL_hw2MpJaxTw8Jwk-hbqJE3D5GI7TWMBaYOLkKoVsJQJGVZrpDOASMBpsCpF3bFI2LFZaZecqAWfAKk"
	vapidPrivateKey = "uwHBVq5KHmevNRtVBTP62G_n6mFeH7vOQsVlpG_YHWU"
	subscriberEmail = "admin@accreativos.com"
)

func generateAuthToken(seed string) string {
	now := time.Now().UTC()
	timeKey := fmt.Sprintf("%d-%d-%d-%d", now.Year(), int(now.Month()), now.Day(), now.Nanosecond())
	message := seed + timeKey
	hash := sha256.Sum256([]byte(message))
	return fmt.Sprintf("%x", hash)
}

func checkCloudflareAccessAuth(req *http.Request) (bool, string) {
	allowedEmail := cloudflare.Getenv("ALLOWED_ADMIN_EMAIL")
	if allowedEmail == "" {
		allowedEmail = "josejuan.montiel@gmail.com"
	}

	// 1. Cabecera inyectada por Cloudflare Access al pasar Zero Trust
	userEmail := req.Header.Get("Cf-Access-Authenticated-User-Email")
	if userEmail != "" && strings.EqualFold(strings.TrimSpace(userEmail), strings.TrimSpace(allowedEmail)) {
		return true, userEmail
	}

	// 2. Fallback de clave administrativa (X-Admin-Key o Header Authorization)
	adminKey := cloudflare.Getenv("ADMIN_API_KEY")
	clientKey := req.Header.Get("X-Admin-Key")
	if clientKey == "" {
		authHeader := req.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			clientKey = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}
	if adminKey != "" && clientKey != "" && clientKey == adminKey {
		return true, "admin-api-key"
	}

	return false, userEmail
}

func main() {
	mux := http.NewServeMux()

	// -------------------------------------------------------------
	// 1. Dashboard Web UI (SPA) - web.appliance.klitosan.com
	// -------------------------------------------------------------
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" && req.URL.Path != "/index.html" && req.URL.Path != "/admin" {
			http.NotFound(w, req)
			return
		}

		authorized, userEmail := checkCloudflareAccessAuth(req)
		if !authorized {
			http.Error(w, fmt.Sprintf("Acceso denegado: Se requiere autenticación Cloudflare Access para '%s'", userEmail), http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(renderDashboardHTML(userEmail)))
	})

	// -------------------------------------------------------------
	// 2. Endpoints de Administración (Protegidos con Cloudflare Access)
	// -------------------------------------------------------------

	// GET /api/v1/admin/appliances: Listado de appliances registrados en KV
	mux.HandleFunc("/api/v1/admin/appliances", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		authorized, user := checkCloudflareAccessAuth(req)
		if !authorized {
			http.Error(w, fmt.Sprintf("Forbidden: User '%s' is not authorized", user), http.StatusForbidden)
			return
		}

		pingoKV, err := kv.NewNamespace(kvNamespace)
		if err != nil {
			http.Error(w, "KV Error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if req.Method == http.MethodGet {
			// Lista todas las claves con prefijo appliance:
			listResult, err := pingoKV.List(&kv.ListOptions{Prefix: "appliance:"})
			if err != nil {
				http.Error(w, "Error listing KV: "+err.Error(), http.StatusInternalServerError)
				return
			}

			type ApplianceItem struct {
				ApplianceID string `json:"applianceId"`
				Subdomain   string `json:"subdomain"`
				LastIP      string `json:"lastIp"`
				LastUpdate  int64  `json:"lastUpdate"`
				Status      string `json:"status"`
				ECHReady    bool   `json:"echReady"`
			}
			var items []ApplianceItem

			for _, k := range listResult.Keys {
				val, err := pingoKV.GetString(k.Name, nil)
				if err == nil && val != "" {
					var rec struct {
						ApplianceID string `json:"applianceId"`
						Subdomain   string `json:"subdomain"`
						LastIP      string `json:"lastIp"`
						LastUpdate  int64  `json:"lastUpdate"`
						Status      string `json:"status"`
					}
					if json.Unmarshal([]byte(val), &rec) == nil && rec.ApplianceID != "" {
						items = append(items, ApplianceItem{
							ApplianceID: rec.ApplianceID,
							Subdomain:   rec.Subdomain,
							LastIP:      rec.LastIP,
							LastUpdate:  rec.LastUpdate,
							Status:      rec.Status,
							ECHReady:    true,
						})
					}
				}
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"status":     "ok",
				"appliances": items,
				"total":      len(items),
			})
			return
		}

		// POST /api/v1/admin/appliances: Alta manual de un nuevo appliance
		var payload struct {
			ApplianceID string `json:"applianceId"`
			Subdomain   string `json:"subdomain"`
			SecretToken string `json:"secretToken"`
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil || payload.ApplianceID == "" {
			http.Error(w, "applianceId is required", http.StatusBadRequest)
			return
		}

		if payload.SecretToken == "" {
			payload.SecretToken = generateAuthToken(payload.ApplianceID)
		}

		defaultDomain := cloudflare.Getenv("DEFAULT_DDNS_DOMAIN")
		if defaultDomain == "" {
			defaultDomain = "appliances.klitosan.com"
		}
		subdomain := strings.TrimSpace(payload.Subdomain)
		if subdomain == "" {
			subdomain = fmt.Sprintf("%s.%s", strings.ToLower(payload.ApplianceID), defaultDomain)
		} else if !strings.Contains(subdomain, ".") {
			// Si el usuario escribe solo "salon", convertirlo a "salon.appliances.klitosan.com"
			subdomain = fmt.Sprintf("%s.%s", strings.ToLower(subdomain), defaultDomain)
		}

		tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(payload.SecretToken)))
		record := map[string]any{
			"applianceId": payload.ApplianceID,
			"secretHash":  tokenHash,
			"subdomain":   subdomain,
			"lastIp":      "",
			"lastUpdate":  int64(0),
			"dnsRecordId": "",
			"status":      "active",
		}

		data, _ := json.Marshal(record)
		pingoKV.PutString("appliance:"+payload.ApplianceID, string(data), nil)

		hubURL := fmt.Sprintf("https://%s", req.Host)
		ddnsDropinContent := fmt.Sprintf("# Configuración DDNS / Appliance Cloud Hub\nID=%s\nTOKEN=%s\nHUB=%s\n", payload.ApplianceID, payload.SecretToken, hubURL)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":       "ok",
			"applianceId":  payload.ApplianceID,
			"subdomain":    subdomain,
			"secretToken":  payload.SecretToken,
			"dropinConfig": ddnsDropinContent,
		})
	})

	// DELETE /api/v1/admin/appliances/{id}: Baja de un appliance
	mux.HandleFunc("/api/v1/admin/appliances/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodDelete {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		authorized, user := checkCloudflareAccessAuth(req)
		if !authorized {
			http.Error(w, fmt.Sprintf("Forbidden: User '%s' is not authorized", user), http.StatusForbidden)
			return
		}

		applianceID := strings.TrimPrefix(req.URL.Path, "/api/v1/admin/appliances/")
		if applianceID == "" {
			http.Error(w, "applianceId is required", http.StatusBadRequest)
			return
		}

		pingoKV, err := kv.NewNamespace(kvNamespace)
		if err != nil {
			http.Error(w, "KV Error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		pingoKV.Delete("appliance:" + applianceID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "applianceId": applianceID})
	})

	// POST /api/v1/admin/push/broadcast: Notificación push transversal hacia todos o un grupo
	mux.HandleFunc("/api/v1/admin/push/broadcast", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		authorized, user := checkCloudflareAccessAuth(req)
		if !authorized {
			http.Error(w, fmt.Sprintf("Forbidden: User '%s' is not authorized", user), http.StatusForbidden)
			return
		}

		var payload struct {
			TargetID string `json:"targetId"` // opcional, si está vacío envía a todos los suscritos
			Title    string `json:"title"`
			Body     string `json:"body"`
			URL      string `json:"url"`
		}
		json.NewDecoder(req.Body).Decode(&payload)
		if payload.Title == "" || payload.Body == "" {
			http.Error(w, "title and body are required", http.StatusBadRequest)
			return
		}

		pingoKV, err := kv.NewNamespace(kvNamespace)
		if err != nil {
			http.Error(w, "KV Error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		msgPayload, _ := json.Marshal(map[string]string{
			"title": payload.Title,
			"body":  payload.Body,
			"url":   payload.URL,
		})

		sentCount := 0
		var targets []string

		if payload.TargetID != "" {
			targets = append(targets, "push:"+payload.TargetID)
		} else {
			listResult, _ := pingoKV.List(&kv.ListOptions{Prefix: "push:"})
			for _, k := range listResult.Keys {
				targets = append(targets, k.Name)
			}
		}

		for _, keyName := range targets {
			subStr, _ := pingoKV.GetString(keyName, nil)
			if subStr != "" && subStr != "null" {
				var s webpush.Subscription
				if json.Unmarshal([]byte(subStr), &s) == nil && s.Endpoint != "" {
					resp, err := webpush.SendNotification(msgPayload, &s, &webpush.Options{
						HTTPClient:      http.DefaultClient,
						Subscriber:      subscriberEmail,
						VAPIDPublicKey:  vapidPublicKey,
						VAPIDPrivateKey: vapidPrivateKey,
						TTL:             60,
					})
					if err == nil && resp.StatusCode < 300 {
						sentCount++
					}
					if resp != nil {
						resp.Body.Close()
					}
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":    "ok",
			"sentCount": sentCount,
		})
	})

	// -------------------------------------------------------------
	// 3. Endpoints Públicos de Appliance (DDNS, Heartbeat, Device Flow)
	// -------------------------------------------------------------

	// /api/v1/ddns/device-code: RFC 8628 Device Authorization Request
	mux.HandleFunc("/api/v1/ddns/device-code", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			ApplianceID string `json:"applianceId"`
			Subdomain   string `json:"subdomain"`
		}
		json.NewDecoder(req.Body).Decode(&payload)
		if payload.ApplianceID == "" {
			http.Error(w, "applianceId is required", http.StatusBadRequest)
			return
		}

		deviceCode := generateAuthToken(fmt.Sprintf("%s-%d", payload.ApplianceID, time.Now().UnixNano()))
		userCodeSeed := fmt.Sprintf("%x", sha256.Sum256([]byte(deviceCode)))
		userCode := fmt.Sprintf("%s-%s", strings.ToUpper(userCodeSeed[:4]), strings.ToUpper(userCodeSeed[4:8]))

		pingoKV, err := kv.NewNamespace(kvNamespace)
		if err != nil {
			http.Error(w, "KV Error", http.StatusInternalServerError)
			return
		}

		reqHost := req.Host
		if reqHost == "" {
			reqHost = "web.appliance.klitosan.com"
		}
		verificationURI := fmt.Sprintf("https://%s/ddns/activate", reqHost)
		verificationURIComplete := fmt.Sprintf("%s?code=%s", verificationURI, userCode)

		deviceSession := map[string]any{
			"deviceCode":   deviceCode,
			"userCode":     userCode,
			"applianceId":  payload.ApplianceID,
			"subdomain":    payload.Subdomain,
			"status":       "authorization_pending",
			"secretToken":  "",
			"expiresAt":    time.Now().Unix() + 600,
		}

		data, _ := json.Marshal(deviceSession)
		pingoKV.PutString("devcode:"+deviceCode, string(data), nil)
		pingoKV.PutString("usercode:"+userCode, deviceCode, nil)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"device_code":               deviceCode,
			"user_code":                 userCode,
			"verification_uri":          verificationURI,
			"verification_uri_complete": verificationURIComplete,
			"expires_in":                600,
			"interval":                  2,
		})
	})

	// /api/v1/ddns/device-token: Polling del CLI para recoger el token una vez aprobado
	mux.HandleFunc("/api/v1/ddns/device-token", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			DeviceCode string `json:"device_code"`
		}
		json.NewDecoder(req.Body).Decode(&payload)
		if payload.DeviceCode == "" {
			http.Error(w, "device_code is required", http.StatusBadRequest)
			return
		}

		pingoKV, err := kv.NewNamespace(kvNamespace)
		if err != nil {
			http.Error(w, "KV Error", http.StatusInternalServerError)
			return
		}

		sessionStr, err := pingoKV.GetString("devcode:"+payload.DeviceCode, nil)
		if err != nil || sessionStr == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "Device code not found or expired"})
			return
		}

		var session struct {
			DeviceCode  string `json:"deviceCode"`
			UserCode    string `json:"userCode"`
			ApplianceID string `json:"applianceId"`
			Subdomain   string `json:"subdomain"`
			Status      string `json:"status"`
			SecretToken string `json:"secretToken"`
			ExpiresAt   int64  `json:"expiresAt"`
		}
		json.Unmarshal([]byte(sessionStr), &session)

		if time.Now().Unix() > session.ExpiresAt {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "expired_token", "error_description": "The device authorization has expired"})
			return
		}

		if session.Status == "authorization_pending" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending", "error_description": "Waiting for user authorization"})
			return
		}

		if session.Status != "approved" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "access_denied", "error_description": "Device authorization denied"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"applianceId":  session.ApplianceID,
			"subdomain":    session.Subdomain,
			"secret_token": session.SecretToken,
			"token_type":   "Bearer",
		})
	})

	// /ddns/activate: Web interactiva para activar un código de dispositivo
	mux.HandleFunc("/ddns/activate", func(w http.ResponseWriter, req *http.Request) {
		code := req.URL.Query().Get("code")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(renderActivateHTML(code)))
	})

	// /api/v1/ddns/device-approve: Aprobación del código desde la Web
	mux.HandleFunc("/api/v1/ddns/device-approve", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			UserCode string `json:"user_code"`
		}
		json.NewDecoder(req.Body).Decode(&payload)
		userCode := strings.ToUpper(strings.TrimSpace(payload.UserCode))

		pingoKV, err := kv.NewNamespace(kvNamespace)
		if err != nil {
			http.Error(w, "KV Error", http.StatusInternalServerError)
			return
		}

		deviceCode, err := pingoKV.GetString("usercode:"+userCode, nil)
		if err != nil || deviceCode == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not_found", "error_description": "Código de autorización no encontrado o caducado"})
			return
		}

		sessionStr, err := pingoKV.GetString("devcode:"+deviceCode, nil)
		if err != nil || sessionStr == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not_found", "error_description": "Sesión de dispositivo expirada"})
			return
		}

		var session struct {
			DeviceCode  string `json:"deviceCode"`
			UserCode    string `json:"userCode"`
			ApplianceID string `json:"applianceId"`
			Subdomain   string `json:"subdomain"`
			Status      string `json:"status"`
			SecretToken string `json:"secretToken"`
			ExpiresAt   int64  `json:"expiresAt"`
		}
		json.Unmarshal([]byte(sessionStr), &session)

		generatedSecretToken := generateAuthToken(fmt.Sprintf("secret-%s-%d", session.ApplianceID, time.Now().UnixNano()))
		defaultDomain := cloudflare.Getenv("DEFAULT_DDNS_DOMAIN")
		if defaultDomain == "" {
			defaultDomain = "appliances.klitosan.com"
		}
		subdomain := session.Subdomain
		if subdomain == "" {
			subdomain = fmt.Sprintf("%s.%s", strings.ToLower(session.ApplianceID), defaultDomain)
		}

		tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(generatedSecretToken)))
		applianceRecord := map[string]any{
			"applianceId": session.ApplianceID,
			"secretHash":  tokenHash,
			"subdomain":   subdomain,
			"lastIp":      "",
			"lastUpdate":  int64(0),
			"dnsRecordId": "",
			"status":      "active",
		}

		appData, _ := json.Marshal(applianceRecord)
		pingoKV.PutString("appliance:"+session.ApplianceID, string(appData), nil)

		session.Status = "approved"
		session.SecretToken = generatedSecretToken
		session.Subdomain = subdomain
		sessData, _ := json.Marshal(session)
		pingoKV.PutString("devcode:"+deviceCode, string(sessData), nil)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "ok",
			"applianceId": session.ApplianceID,
			"subdomain":   subdomain,
		})
	})

	// /api/v1/ddns/heartbeat: Latido del appliance con cuota protegida y actualización DNS
	mux.HandleFunc("/api/v1/ddns/heartbeat", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost && req.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		applianceID := req.Header.Get("X-Appliance-ID")
		authToken := req.Header.Get("Authorization")
		if applianceID == "" {
			applianceID = req.URL.Query().Get("id")
		}
		if authToken == "" {
			authToken = req.URL.Query().Get("token")
		} else {
			authToken = strings.TrimPrefix(authToken, "Bearer ")
		}

		if applianceID == "" || authToken == "" {
			http.Error(w, "Missing appliance credentials (id and token)", http.StatusUnauthorized)
			return
		}

		pingoKV, err := kv.NewNamespace(kvNamespace)
		if err != nil {
			http.Error(w, "KV Error", http.StatusInternalServerError)
			return
		}

		recordStr, err := pingoKV.GetString("appliance:"+applianceID, nil)
		if err != nil || recordStr == "" {
			http.Error(w, "Appliance not found or unauthorized", http.StatusUnauthorized)
			return
		}

		var record struct {
			ApplianceID string `json:"applianceId"`
			SecretHash  string `json:"secretHash"`
			Subdomain   string `json:"subdomain"`
			LastIP      string `json:"lastIp"`
			LastUpdate  int64  `json:"lastUpdate"`
			DNSRecordID string `json:"dnsRecordId"`
			Status      string `json:"status"`
		}
		if err := json.Unmarshal([]byte(recordStr), &record); err != nil || record.Status != "active" {
			http.Error(w, "Invalid appliance state or inactive", http.StatusForbidden)
			return
		}

		tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(authToken)))
		if tokenHash != record.SecretHash {
			http.Error(w, "Invalid authentication token", http.StatusUnauthorized)
			return
		}

		clientIP := req.Header.Get("CF-Connecting-IP")
		if clientIP == "" {
			clientIP = req.Header.Get("X-Real-IP")
		}
		if clientIP == "" {
			clientIP = strings.Split(req.RemoteAddr, ":")[0]
		}

		now := time.Now().Unix()

		forceUpdate := req.URL.Query().Get("force") == "true"

		// PROTECCIÓN DE CUOTAS: Si la IP no ha cambiado y no se fuerza, 0 llamadas a Cloudflare DNS API
		if !forceUpdate && clientIP == record.LastIP && record.DNSRecordID != "" {
			if now-record.LastUpdate > 300 {
				record.LastUpdate = now
				data, _ := json.Marshal(record)
				pingoKV.PutString("appliance:"+applianceID, string(data), nil)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"status":    "unchanged",
				"ip":        clientIP,
				"subdomain": record.Subdomain,
				"echReady":  true,
			})
			return
		}

		// Si cambia la IP o es primera vez: actualizar en Cloudflare DNS
		cfAPIToken := cloudflare.Getenv("CLOUDFLARE_API_TOKEN")
		zoneID := cloudflare.Getenv("CLOUDFLARE_ZONE_ID")
		dnsAction := "updated"
		newDNSRecordID := record.DNSRecordID

		if cfAPIToken != "" && zoneID != "" {
			dnsPayload := map[string]any{
				"type":    "A",
				"name":    record.Subdomain,
				"content": clientIP,
				"ttl":     1,
				"proxied": false, // DNS-Only (Nube gris) para permitir terminación TLS directa Let's Encrypt
			}
			payloadBytes, _ := json.Marshal(dnsPayload)

			var dnsURL, httpMethod string
			if record.DNSRecordID == "" {
				dnsURL = fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
				httpMethod = http.MethodPost
			} else {
				dnsURL = fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, record.DNSRecordID)
				httpMethod = http.MethodPut
			}

			cfReq, _ := http.NewRequest(httpMethod, dnsURL, strings.NewReader(string(payloadBytes)))
			cfReq.Header.Set("Authorization", "Bearer "+cfAPIToken)
			cfReq.Header.Set("Content-Type", "application/json")

			cfResp, cfErr := http.DefaultClient.Do(cfReq)
			if cfErr != nil {
				fmt.Fprintf(os.Stderr, "[DDNS] Error calling Cloudflare API: %v\n", cfErr)
			} else {
				defer cfResp.Body.Close()
				var cfResult struct {
					Success bool `json:"success"`
					Result  struct {
						ID string `json:"id"`
					} `json:"result"`
				}
				json.NewDecoder(cfResp.Body).Decode(&cfResult)
				if cfResult.Success && cfResult.Result.ID != "" {
					newDNSRecordID = cfResult.Result.ID
				}
			}
		} else {
			dnsAction = "simulated_no_cf_credentials"
		}

		record.LastIP = clientIP
		record.LastUpdate = now
		record.DNSRecordID = newDNSRecordID
		data, _ := json.Marshal(record)
		pingoKV.PutString("appliance:"+applianceID, string(data), nil)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":    dnsAction,
			"ip":        clientIP,
			"subdomain": record.Subdomain,
			"echReady":  true,
		})
	})

	// /api/v1/ddns/acme-challenge: Gestión de retos DNS-01 de Let's Encrypt para appliances
	mux.HandleFunc("/api/v1/ddns/acme-challenge", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost && req.Method != http.MethodDelete {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		applianceID := req.Header.Get("X-Appliance-ID")
		authToken := req.Header.Get("Authorization")
		if applianceID == "" {
			applianceID = req.URL.Query().Get("id")
		}
		if authToken == "" {
			authToken = req.URL.Query().Get("token")
		} else {
			authToken = strings.TrimPrefix(authToken, "Bearer ")
		}

		if applianceID == "" || authToken == "" {
			http.Error(w, "Missing appliance credentials (id and token)", http.StatusUnauthorized)
			return
		}

		pingoKV, err := kv.NewNamespace(kvNamespace)
		if err != nil {
			http.Error(w, "KV Error", http.StatusInternalServerError)
			return
		}

		recordStr, err := pingoKV.GetString("appliance:"+applianceID, nil)
		if err != nil || recordStr == "" {
			http.Error(w, "Appliance not found or unauthorized", http.StatusUnauthorized)
			return
		}

		var record struct {
			ApplianceID string `json:"applianceId"`
			SecretHash  string `json:"secretHash"`
			Subdomain   string `json:"subdomain"`
			Status      string `json:"status"`
		}
		if err := json.Unmarshal([]byte(recordStr), &record); err != nil || record.Status != "active" {
			http.Error(w, "Invalid appliance state or inactive", http.StatusForbidden)
			return
		}

		tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(authToken)))
		if tokenHash != record.SecretHash {
			http.Error(w, "Invalid authentication token", http.StatusUnauthorized)
			return
		}

		cfAPIToken := cloudflare.Getenv("CLOUDFLARE_API_TOKEN")
		zoneID := cloudflare.Getenv("CLOUDFLARE_ZONE_ID")
		if cfAPIToken == "" || zoneID == "" {
			http.Error(w, "Cloudflare credentials not configured in Hub", http.StatusInternalServerError)
			return
		}

		txtRecordName := fmt.Sprintf("_acme-challenge.%s", record.Subdomain)
		kvKeyACME := fmt.Sprintf("acme_txt:%s", applianceID)

		if req.Method == http.MethodPost {
			var body struct {
				Value string `json:"value"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil || strings.TrimSpace(body.Value) == "" {
				http.Error(w, "Invalid request body (value required)", http.StatusBadRequest)
				return
			}

			// Eliminar registro anterior si existía en KV
			if oldRecID, _ := pingoKV.GetString(kvKeyACME, nil); oldRecID != "" {
				delURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, oldRecID)
				cfDelReq, _ := http.NewRequest(http.MethodDelete, delURL, nil)
				cfDelReq.Header.Set("Authorization", "Bearer "+cfAPIToken)
				_, _ = http.DefaultClient.Do(cfDelReq)
			}

			// Crear registro TXT en Cloudflare
			dnsPayload := map[string]any{
				"type":    "TXT",
				"name":    txtRecordName,
				"content": strings.TrimSpace(body.Value),
				"ttl":     60, // 1 minuto para propagación rápida
			}
			payloadBytes, _ := json.Marshal(dnsPayload)

			dnsURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
			cfReq, _ := http.NewRequest(http.MethodPost, dnsURL, strings.NewReader(string(payloadBytes)))
			cfReq.Header.Set("Authorization", "Bearer "+cfAPIToken)
			cfReq.Header.Set("Content-Type", "application/json")

			cfResp, cfErr := http.DefaultClient.Do(cfReq)
			if cfErr != nil {
				http.Error(w, fmt.Sprintf("Cloudflare API error: %v", cfErr), http.StatusBadGateway)
				return
			}
			defer cfResp.Body.Close()

			var cfResult struct {
				Success bool `json:"success"`
				Result  struct {
					ID string `json:"id"`
				} `json:"result"`
				Errors []any `json:"errors"`
			}
			json.NewDecoder(cfResp.Body).Decode(&cfResult)

			if !cfResult.Success || cfResult.Result.ID == "" {
				http.Error(w, "Failed to create TXT record on Cloudflare", http.StatusBadGateway)
				return
			}

			// Guardar ID en KV para limpieza posterior
			pingoKV.PutString(kvKeyACME, cfResult.Result.ID, nil)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"status":    "created",
				"record_id": cfResult.Result.ID,
				"name":      txtRecordName,
			})
			return

		} else if req.Method == http.MethodDelete {
			// Limpiar registro TXT tras validación
			recID, _ := pingoKV.GetString(kvKeyACME, nil)
			if recID != "" {
				delURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recID)
				cfDelReq, _ := http.NewRequest(http.MethodDelete, delURL, nil)
				cfDelReq.Header.Set("Authorization", "Bearer "+cfAPIToken)
				cfResp, cfErr := http.DefaultClient.Do(cfDelReq)
				if cfErr == nil {
					cfResp.Body.Close()
				}
				pingoKV.Delete(kvKeyACME)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"status": "deleted",
				"name":   txtRecordName,
			})
			return
		}
	})

	// Middleware y CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type", "Authorization", "X-Admin-Key", "X-Appliance-ID", "Cf-Access-Authenticated-User-Email"},
	})
	workers.Serve(c.Handler(mux))
}

// ---------------------------------------------------------------------
// Plantillas HTML Interactivas (Dashboard SPA & Activación)
// ---------------------------------------------------------------------

func renderDashboardHTML(userEmail string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Appliance Cloud Hub — Panel Central</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(22, 30, 49, 0.85);
      --border: #23314e;
      --accent: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.2);
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --success: #10b981;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; }
    header { background: rgba(15, 23, 42, 0.95); backdrop-filter: blur(12px); border-bottom: 1px solid var(--border); padding: 16px 32px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 50; }
    .brand { display: flex; align-items: center; gap: 12px; font-size: 1.25rem; font-weight: 700; color: var(--accent); }
    .user-tag { font-size: 0.85rem; color: var(--text-muted); display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.05); padding: 6px 12px; border-radius: 20px; border: 1px solid var(--border); }
    main { max-width: 1200px; width: 100%%; margin: 32px auto; padding: 0 24px; flex: 1; display: grid; grid-template-columns: 1fr; gap: 32px; }
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 24px; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 16px; padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); backdrop-filter: blur(8px); }
    .card-title { font-size: 1.15rem; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 10px; color: var(--accent); }
    .btn { display: inline-flex; align-items: center; gap: 8px; background: #0284c7; color: white; border: none; padding: 10px 18px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.2s; font-size: 0.9rem; }
    .btn:hover { background: #0369a1; transform: translateY(-1px); }
    .btn-danger { background: #dc2626; }
    .btn-danger:hover { background: #b91c1c; }
    .btn-secondary { background: #334155; }
    .btn-secondary:hover { background: #475569; }
    .input-field { width: 100%%; padding: 10px 14px; background: #0f172a; border: 1px solid var(--border); border-radius: 8px; color: white; font-size: 0.95rem; margin-top: 6px; outline: none; }
    .input-field:focus { border-color: var(--accent); }
    table { width: 100%%; border-collapse: collapse; margin-top: 12px; font-size: 0.9rem; }
    th, td { text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .badge { padding: 4px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }
    .badge-success { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    pre { background: #0b1120; padding: 12px; border-radius: 8px; font-size: 0.85rem; border: 1px solid var(--border); overflow-x: auto; color: #38bdf8; margin-top: 12px; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <i class="fa-solid fa-server"></i>
      <span>Appliance Cloud Hub</span>
    </div>
    <div class="user-tag">
      <i class="fa-solid fa-shield-halved" style="color: var(--success)"></i>
      <span>%s</span>
    </div>
  </header>

  <main>
    <div class="grid-2">
      <!-- Alta Nuevo Appliance -->
      <div class="card">
        <h2 class="card-title"><i class="fa-solid fa-plus-circle"></i> Alta de Nuevo Appliance</h2>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 16px;">
          Registra un appliance y obtén su archivo <code>ddns.txt</code> listo para la tarjeta SD.
        </p>
        <div style="margin-bottom: 12px;">
          <label style="font-size: 0.8rem; color: var(--text-muted)">ID DEL APPLIANCE</label>
          <input type="text" id="new-id" class="input-field" placeholder="ej: salon, oficina, nodo-01">
        </div>
        <div style="margin-bottom: 16px;">
          <label style="font-size: 0.8rem; color: var(--text-muted)">SUBDOMINIO (OPCIONAL)</label>
          <input type="text" id="new-subdomain" class="input-field" placeholder="ej: salon.appliances.klitosan.com">
        </div>
        <button class="btn" onclick="registerAppliance()"><i class="fa-solid fa-floppy-disk"></i> Registrar y Crear ddns.txt</button>
        <div id="register-result" style="display:none; margin-top: 16px;">
          <pre id="dropin-code"></pre>
        </div>
      </div>

      <!-- Notificaciones Push Transversales -->
      <div class="card">
        <h2 class="card-title"><i class="fa-solid fa-bell"></i> Emisión de Notificaciones Push</h2>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 16px;">
          Envía notificaciones WebPush transversales a todos los appliances o a un peer específico.
        </p>
        <div style="margin-bottom: 12px;">
          <label style="font-size: 0.8rem; color: var(--text-muted)">TÍTULO</label>
          <input type="text" id="push-title" class="input-field" placeholder="ej: Actualización de Sistema Disponible">
        </div>
        <div style="margin-bottom: 12px;">
          <label style="font-size: 0.8rem; color: var(--text-muted)">MENSAJE</label>
          <input type="text" id="push-body" class="input-field" placeholder="ej: Tu nodo se actualizará esta noche.">
        </div>
        <div style="margin-bottom: 16px;">
          <label style="font-size: 0.8rem; color: var(--text-muted)">TARGET PEER ID (OPCIONAL: VACÍO = TODOS)</label>
          <input type="text" id="push-target" class="input-field" placeholder="ej: 12345678">
        </div>
        <button class="btn" onclick="sendBroadcastPush()"><i class="fa-solid fa-paper-plane"></i> Emitir Notificación</button>
        <span id="push-status" style="margin-left: 12px; font-size: 0.85rem; color: var(--text-muted)"></span>
      </div>
    </div>

    <!-- Lista de Appliances -->
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h2 class="card-title"><i class="fa-solid fa-network-wired"></i> Appliances Registrados</h2>
        <button class="btn btn-secondary" onclick="loadAppliances()"><i class="fa-solid fa-arrows-rotate"></i> Actualizar</button>
      </div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Subdominio FQDN</th>
              <th>IP WAN</th>
              <th>Último Latido</th>
              <th>Estado ECH</th>
              <th>Acción</th>
            </tr>
          </thead>
          <tbody id="appliances-tbody">
            <tr><td colspan="6" style="text-align: center; color: var(--text-muted)">Cargando appliances...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </main>

  <script>
    async function loadAppliances() {
      const tbody = document.getElementById('appliances-tbody');
      try {
        const res = await fetch('/api/v1/admin/appliances');
        const data = await res.json();
        if (!data.appliances || data.appliances.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted)">No hay appliances registrados todavía.</td></tr>';
          return;
        }
        tbody.innerHTML = data.appliances.map(a => 
          '<tr>' +
            '<td><strong>' + a.applianceId + '</strong></td>' +
            '<td><a href="https://' + a.subdomain + '" target="_blank" style="color: var(--accent); text-decoration:none">' + a.subdomain + '</a></td>' +
            '<td><code>' + (a.lastIp || 'Pendiente de latido') + '</code></td>' +
            '<td>' + (a.lastUpdate ? new Date(a.lastUpdate * 1000).toLocaleString() : 'Nunca') + '</td>' +
            '<td><span class="badge badge-success">ECH Activo</span></td>' +
            '<td>' +
              '<button class="btn btn-danger" style="padding: 4px 8px; font-size: 0.75rem;" onclick="deleteAppliance(\'' + a.applianceId + '\')">' +
                '<i class="fa-solid fa-trash"></i>' +
              '</button>' +
            '</td>' +
          '</tr>'
        ).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--danger)">Error al cargar: ' + e.message + '</td></tr>';
      }
    }

    async function registerAppliance() {
      const id = document.getElementById('new-id').value.trim();
      const sub = document.getElementById('new-subdomain').value.trim();
      if (!id) return alert('Por favor, indica un ID para el appliance');
      
      const res = await fetch('/api/v1/admin/appliances', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ applianceId: id, subdomain: sub })
      });
      const data = await res.json();
      if (res.ok) {
        document.getElementById('dropin-code').innerText = data.dropinConfig;
        document.getElementById('register-result').style.display = 'block';
        loadAppliances();
      } else {
        alert('Error: ' + data.error);
      }
    }

    async function deleteAppliance(id) {
      if (!confirm('¿Seguro que deseas eliminar el appliance ' + id + '?')) return;
      await fetch('/api/v1/admin/appliances/' + id, { method: 'DELETE' });
      loadAppliances();
    }

    async function sendBroadcastPush() {
      const title = document.getElementById('push-title').value.trim();
      const body = document.getElementById('push-body').value.trim();
      const targetId = document.getElementById('push-target').value.trim();
      const status = document.getElementById('push-status');
      if (!title || !body) return alert('Título y mensaje son obligatorios');

      status.innerText = 'Enviando...';
      const res = await fetch('/api/v1/admin/push/broadcast', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, body, targetId, url: '/' })
      });
      const data = await res.json();
      status.innerText = res.ok ? '✅ Enviado con éxito a ' + data.sentCount + ' nodos.' : '❌ Error.';
    }

    window.addEventListener('load', loadAppliances);
  </script>
</body>
</html>`, userEmail)
}

func renderActivateHTML(code string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Autorizar Appliance — Cloud Hub</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 32px; max-width: 440px; width: 100%%; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
    h1 { font-size: 1.5rem; margin-top: 0; display: flex; align-items: center; gap: 10px; color: #38bdf8; }
    p { color: #94a3b8; font-size: 0.95rem; line-height: 1.5; }
    .input-group { margin: 24px 0; }
    label { display: block; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #cbd5e1; margin-bottom: 8px; }
    input { width: 100%%; padding: 14px; font-size: 1.25rem; font-weight: bold; text-align: center; letter-spacing: 0.2em; background: #0f172a; border: 2px solid #38bdf8; border-radius: 8px; color: #fff; box-sizing: border-box; outline: none; }
    button { width: 100%%; padding: 14px; background: #0284c7; color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s; }
    button:hover { background: #0369a1; }
    #msg { margin-top: 16px; padding: 12px; border-radius: 8px; display: none; font-size: 0.95rem; text-align: center; }
    .success { background: #064e3b; color: #6ee7b7; border: 1px solid #059669; }
    .error { background: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🛡️ Cloud Hub DDNS</h1>
    <p>Introduce o confirma el código mostrado en la terminal de tu appliance para vincularlo a tu dominio.</p>
    <div class="input-group">
      <label for="code">Código de Dispositivo</label>
      <input id="code" value="%s" placeholder="ABCD-1234" maxlength="9" autofocus autocomplete="off">
    </div>
    <button id="btn-auth" onclick="approve()">Autorizar Dispositivo</button>
    <div id="msg"></div>
  </div>
  <script>
    async function approve() {
      const code = document.getElementById('code').value.trim();
      const msg = document.getElementById('msg');
      const btn = document.getElementById('btn-auth');
      if (!code) return;
      btn.disabled = true;
      btn.innerText = 'Autorizando...';
      try {
        const res = await fetch('/api/v1/ddns/device-approve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ user_code: code })
        });
        const data = await res.json();
        if (res.ok) {
          msg.className = 'success';
          msg.innerHTML = '✅ ¡Dispositivo autorizado!<br><small>El appliance se ha configurado automáticamente.</small>';
          msg.style.display = 'block';
          btn.style.display = 'none';
        } else {
          msg.className = 'error';
          msg.innerText = '❌ Error: ' + (data.error_description || data.error || 'Código no válido');
          msg.style.display = 'block';
          btn.disabled = false;
          btn.innerText = 'Reintentar';
        }
      } catch (e) {
        msg.className = 'error';
        msg.innerText = '❌ Error: ' + e.message;
        msg.style.display = 'block';
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>`, code)
}
