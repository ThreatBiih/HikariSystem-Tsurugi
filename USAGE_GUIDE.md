# 🗡️ HikariSystem TSURUGI v3.0 - Guia de Uso Completo

## Instalação Rápida

```bash
cd "HikariSystem TSURUGI"
pip install -r requirements.txt
playwright install chromium  # Necessário para --confirm, --heavy, --cf-bypass
```

---

## Comandos Principais

### 1️⃣ SQLi (SQL Injection)

```bash
# Básico
python tsurugi.py attack "http://alvo.com/page?id=1"

# Com cookie de sessão
python tsurugi.py --cookie "PHPSESSID=abc123" attack "http://alvo.com/page?id=1"

# Com proxy (Burp)
python tsurugi.py --proxy "http://127.0.0.1:8080" attack "http://alvo.com/page?id=1"

# Modo stealth (delays + headers randômicos)
python tsurugi.py --stealth attack "http://alvo.com/page?id=1"

# Bypass Cloudflare
python tsurugi.py --cf-bypass attack "http://alvo.com/page?id=1"

# Detecção OOB (blind SQLi com Interactsh)
python tsurugi.py --oob attack "http://alvo.com/page?id=1"
```

---

### 2️⃣ XSS (Cross-Site Scripting)

```bash
# Básico - detecta reflections
python tsurugi.py xss "http://alvo.com/search?q=test"

# ⭐ COM CONFIRMAÇÃO EM BROWSER (zero falsos positivos!) ⭐
python tsurugi.py xss "http://alvo.com/search?q=test" --confirm

# Com OOB (blind XSS)
python tsurugi.py --oob xss "http://alvo.com/search?q=test"

# Stealth + confirmação
python tsurugi.py --stealth xss "http://alvo.com/search?q=test" --confirm
```

**`--confirm`:** Abre Playwright, executa payload, escuta `dialog` event. Se popup aparecer → XSS confirmado + screenshot.

---

### 3️⃣ LFI (Local File Inclusion)

```bash
# Básico
python tsurugi.py lfi "http://alvo.com/page?file=home"

# Com cookie
python tsurugi.py --cookie "session=xyz" lfi "http://alvo.com/page?file=home"
```

---

### 4️⃣ SSTI (Server-Side Template Injection) ✨NEW

```bash
# Básico - detecta Jinja2, Twig, Freemarker, Velocity, etc.
python tsurugi.py ssti "http://alvo.com/render?name=test"

# Com OOB (blind SSTI)
python tsurugi.py --oob ssti "http://alvo.com/render?name=test"
```

---

### 5️⃣ Secrets Scanner ✨NEW

```bash
# Escaneia URL por API keys, tokens, credentials
python tsurugi.py secrets "http://alvo.com/app.js"

# Com VERIFICAÇÃO ATIVA (checa se as keys são válidas!)
python tsurugi.py secrets "http://alvo.com/app.js" --verify

# Com stealth
python tsurugi.py --stealth secrets "http://alvo.com/main.bundle.js" --verify
```

**Detecta:** AWS Keys, Google API, Stripe, GitHub PAT, Slack, Discord, JWT, Private Keys, MongoDB/PostgreSQL URIs, SendGrid, Twilio, Firebase, passwords hardcoded...

**Com `--verify`:** Testa se as keys são válidas chamando as APIs reais (GitHub, Stripe, Slack, Discord, SendGrid, Google, JWT decode).

---

### 6️⃣ Parameter Discovery ✨v3.0

```bash
# Descobre parâmetros ocultos (debug, admin, token, etc)
python tsurugi.py params "http://alvo.com/api/user"

# Com mais threads
python tsurugi.py params "http://alvo.com/api" --threads 20
```

**Testa 100+ nomes comuns:** debug, admin, test, token, key, secret, id, page, etc.
**Técnica:** Compara responses (length, status, hash) para detectar comportamento diferente.

---

### 7️⃣ DOM XSS Analysis ✨v3.0

```bash
# Análise estática de JavaScript
python tsurugi.py domxss "http://alvo.com"
```

**Detecta Sinks:** innerHTML, outerHTML, eval, document.write, location.href, jQuery .html()/.append()

**Detecta Sources:** location.search, location.hash, document.referrer, postMessage, localStorage

**Output:** Lista de linhas onde source → sink (potencial DOM XSS)

---

### 8️⃣ Nuclei Scanner ✨v3.0

```bash
# Scan com 6000+ templates de CVEs
python tsurugi.py nuclei "http://alvo.com"

# Específico (CVEs, exposures, misconfigs)
python tsurugi.py nuclei "http://alvo.com" --templates cves,exposures

# Só critical/high
python tsurugi.py nuclei "http://alvo.com" --severity critical,high
```

**Requer:** `nuclei` instalado (`go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`)

---

### 9️⃣ Crawler (Descoberta de Endpoints)

```bash
# Básico - retorna URLs com parâmetros GET, formulários POST, e rotas JS
python tsurugi.py crawl "http://alvo.com"

# Profundidade maior
python tsurugi.py crawl "http://alvo.com" --depth 3

# Com JS rendering (SPAs)
python tsurugi.py --heavy crawl "http://alvo.com"
```

---

### 6️⃣ Mass Check (Scan em Massa)

```bash
# SQLi em lista de URLs
python tsurugi.py mass_check urls.txt --module sqli --threads 10

# XSS em lista
python tsurugi.py mass_check urls.txt --module xss --threads 5

# LFI em lista
python tsurugi.py mass_check urls.txt --module lfi --threads 10

# SSTI em lista ✨NEW
python tsurugi.py mass_check urls.txt --module ssti --threads 5
```

**Formato do arquivo `urls.txt`:**
```
http://site1.com/page?id=1
http://site2.com/search?q=test
http://site3.com/view?file=home
```

---

### 7️⃣ Nmap + Service Analysis

```bash
# Scan de rede
python tsurugi.py nmap 192.168.1.0/24

# Analisa resultado do Nmap
python tsurugi.py analyze nmap_output.xml
```

---

### 8️⃣ Hunter Protocol (Nuclei + Subfinder)

```bash
# Recon completo com ferramentas externas
python tsurugi.py hunter target.com

# Incluir vulns medium/low
python tsurugi.py hunter target.com --full
```

**Requer:** `subfinder` e `nuclei` instalados no PATH.

---

### 9️⃣ Novos Módulos v3.1 (Jan 2026) ✨

#### **Security Headers**
Detecção de headers ausentes ou inseguros e cálculo de score.
```bash
python tsurugi.py headers "https://alvo.com"
```

#### **CORS Scanner**
Verifica 8 tipos de misconfiguration em Access-Control-Allow-Origin.
```bash
python tsurugi.py cors "https://alvo.com"
```

#### **API Discovery**
Busca endpoints em arquivos JS usando regex avançado.
```bash
python tsurugi.py api "https://alvo.com"
```

#### **SSRF Scanner (Server-Side Request Forgery)**
Testa injection em headers, parâmetros e cloud metadata.
```bash
python tsurugi.py ssrf "https://alvo.com/webhook?url=test" --oob
```

#### **Open Redirect**
Testa bypasses (//, %2e%2e, etc) em parâmetros de redirecionamento.
```bash
python tsurugi.py redirect "https://alvo.com/login?next=/"
```

#### **Advanced Directory Fuzzer**
Multi-thread brute-force para achar admin panels e arquivos .env/backup.
```bash
python tsurugi.py fuzz "https://alvo.com" --ext --threads 50
```

---

### 🔟 Gerar Relatório

```bash
python tsurugi.py report
```

Gera HTML com todos os findings salvos em `loot/`.

---

## Flags Globais

| Flag | Descrição |
|------|-----------|
| `--cookie`, `-c` | Cookie de sessão (ex: `PHPSESSID=abc`) |
| `--proxy`, `-p` | Proxy URL (ex: `http://127.0.0.1:8080`) |
| `--verbose`, `-v` | Output verboso |
| `--oob` | Habilita detecção OOB via Interactsh |
| `--heavy` | Usa headless browser (Playwright) |
| `--stealth`, `-s` | Modo evasivo (delays + header rotation) ✨NEW |
| `--cf-bypass` | Bypass Cloudflare automático ✨NEW |

---

## Fluxo Típico de Bug Bounty

```bash
# 1. Crawl o alvo
python tsurugi.py crawl "https://target.com" --depth 2 > endpoints.txt

# 2. Extraia URLs com parâmetros
# (o crawl já mostra organizadas)

# 3. Teste SQLi nas URLs
python tsurugi.py --stealth attack "https://target.com/api?id=1"

# 4. Teste XSS
python tsurugi.py --stealth xss "https://target.com/search?q=test"

# 5. Teste SSTI (se tiver templates)
python tsurugi.py --stealth ssti "https://target.com/preview?name=test"

# 6. Mass scan se tiver muitas URLs
python tsurugi.py mass_check urls.txt --module sqli --threads 5

# 7. Gerar relatório
python tsurugi.py report
```

---

## Dicas de Performance

| Situação | Solução |
|----------|---------|
| Site com rate limit | Use `--stealth` (adiciona delays) |
| Cloudflare/WAF | Use `--cf-bypass` |
| SPA/React/Angular | Use `--heavy` |
| Blind vulns | Use `--oob` |
| Scan lento | Aumente `--threads` no mass_check |

---

## Troubleshooting

**"No module named 'playwright'"**
```bash
pip install playwright
playwright install chromium
```

**"No module named 'cloudscraper'"**
```bash
pip install cloudscraper
```

**OOB não funciona**
- Verifique conexão com internet
- O servidor Interactsh (interact.sh) precisa estar acessível

---

## Onde ficam os resultados?

- **Findings JSON:** `loot/` (um arquivo por vuln)
- **Relatório HTML:** `reports/` (gerado com `report`)
