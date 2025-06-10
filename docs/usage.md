bash```
╔╦╗┬─┐┬╔╗╔┌─┐┌┬┐┬─┐┌─┐
 ║ ├┬┘│║║║├┤  │ ├┬┘├─┤
 ╩ ┴└─┴╝╚╝└─┘ ┴ ┴└─┴ ┴
T h e   T h i r d   E y e   O f   S e e   B e y o n d   T h e   S u r f a c e... 🔎 🌐

Author : Debajyoti0-0
Github : https://github.com/Debajyoti0-0
=====================================================================================================================

usage: TriNetra.py [-h] [-m BULKFILE] [-r REQUESTFILE] [--method METHOD] [--http2] [--random-agent] [-A USER_AGENT]
                   [-H HEADER] [--proxy PROXY] [--insecure] [--chunked] [--depth DEPTH] [-t THREADS] [-v]
                   [--no-robots] [--tor] [--tor-port TOR_PORT] [--tor-type {HTTP,SOCKS4,SOCKS5}] [--check-tor]
                   [--delay DELAY] [--timeout TIMEOUT] [--retries RETRIES] [--retry-on RETRY_ON] [-dr] [-i] [-s]
                   [-size PAGE_SIZE] [-subs] [-u] [-w] [--csrf-token CSRF_TOKEN] [--csrf-url CSRF_URL]
                   [--csrf-method CSRF_METHOD] [--csrf-data CSRF_DATA] [--csrf-retries CSRF_RETRIES] [-o OUTPUT]
                   [--csv CSV]
                   [url]

[*] Discover hidden endpoints on a website.

positional arguments:
  url                   Single target URL (e.g. https://example.com) (default: None)

options:
  -h, --help            show this help message and exit
  -m, --bulkfile BULKFILE
                        File with multiple target URLs (one per line) (default: None)
  -r, --requestfile REQUESTFILE
                        Load raw HTTP request from file (default: None)
  --method METHOD       HTTP method to use (GET, POST, etc.) (default: GET)
  --http2               Use HTTP/2 (requires httpx) (default: False)
  --random-agent        Pick a random User-Agent header (default: False)
  -A, --user-agent USER_AGENT
                        Custom User-Agent header value (default: None)
  -H, --header HEADER   Extra headers separated by ';;' (default: None)
  --proxy PROXY         Proxy URL (e.g. http://127.0.0.1:8080) (default: None)
  --insecure            Disable SSL verification (default: False)
  --chunked             Use chunked transfer encoding (Note: handled automatically by libs) (default: False)
  --depth DEPTH         Maximum crawl depth (default: 2)
  -t, --threads THREADS
                        Concurrent worker threads (default: 10)
  -v, --verbose         Verbose output (default: False)
  --no-robots           Ignore robots.txt disallow rules (default: True)
  --tor                 Use Tor anonymity network (default: False)
  --tor-port TOR_PORT   Set Tor proxy port (default: 9050)
  --tor-type {HTTP,SOCKS4,SOCKS5}
                        Set Tor proxy type (default: SOCKS5)
  --check-tor           Check if Tor is used properly (default: False)
  --delay DELAY         Delay in seconds between each HTTP request (default: None)
  --timeout TIMEOUT     Seconds to wait before connection timeout (default: 30)
  --retries RETRIES     Retries when a connection timeouts (default: 3)
  --retry-on RETRY_ON   Retry request on regexp matching content (e.g. 'captcha') (default: None)
  -dr, --disable-redirects
                        Disable following HTTP redirects (default: False)
  -i, --only-crawl-inside
                        Only crawl URLs within the initial path (default: False)
  -s, --show-source     Show the source of a URL (alias for -w) (default: False)
  -size, --page-size PAGE_SIZE
                        Page size limit in KB. (default: -1, no limit) (default: -1)
  -subs, --include-subdomains
                        Include subdomains for crawling (default: False)
  -u, --unique-urls     Show only unique URLs across all targets (default: False)
  -w, --show-link-source
                        Show at which link the URL is found (default: False)

CSRF Options:
  --csrf-token CSRF_TOKEN
                        Form/query parameter name that holds anti‑CSRF token (default: None)
  --csrf-url CSRF_URL   URL to fetch anti‑CSRF token from (default: None)
  --csrf-method CSRF_METHOD
                        HTTP method for anti‑CSRF token fetch (default: GET)
  --csrf-data CSRF_DATA
                        POST data for anti‑CSRF token fetch (default: None)
  --csrf-retries CSRF_RETRIES
                        Retries for anti‑CSRF token fetch (default: 0)

Output Options:
  -o, --output OUTPUT   JSON output file for all findings (default: None)
  --csv CSV             Optional CSV output of endpoints only (default: None)
  ```
