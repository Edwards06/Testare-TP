import requests

SITES = [
    # Pagini obișnuite (Părțile 2, 3 și 4)
    "https://example.com",
    "https://httpbin.org/html",
    "https://httpbin.org/json",
    "https://httpbin.org/status/200",
    "https://httpbin.org/redirect/1",
    "https://httpbin.org/delay/2",
    # Pagini care eșuează
    "https://httpbin.org/status/404",
    "https://httpbin.org/status/500",
    "https://httpbin.org/delay/10",
    "http://this-site-does-not-exist.invalid",
    # Anteturi de securitate (Partea 5)
    "https://httpbin.org/response-headers?X-Frame-Options=DENY&X-Content-Type-Options=nosniff",
    "https://httpbin.org/response-headers?x-frame-options=DENY",
    # Răspunde aleatoriu cu 200 sau 500 (Partea 6)
    "https://httpbin.org/status/200,500",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def build_url(host, path):
    """Construiește o adresă HTTPS din host și path."""
    return f"https://{host}/{path.lstrip('/')}"


def is_https(url):
    """Verifică dacă adresa folosește HTTPS."""
    return url.startswith("https://")


def show_response(url):
    """Afișează statusul și tipul conținutului primit."""
    response = requests.get(url)
    print(f"Status: {response.status_code}")
    print(f"Content-Type: {response.headers.get('Content-Type')}")


def check_site(url):
    """Verifică un site și întoarce câteva informații despre răspuns."""
    try:
        response = requests.get(url, timeout=5)
        return {
            "status": response.status_code,
            "content_type": response.headers.get("Content-Type"),
            "length": len(response.content),
            "server": response.headers.get("Server", "unknown"),
        }
    except requests.exceptions.RequestException:
        return {"status": None, "error": "Request failed"}


def scan_sites():
    """Verifică site-urile din listă și afișează un rezumat."""
    results = []
    for site in SITES:
        results.append((site, check_site(site)))

    working_sites = []
    for site, result in results:
        if result["status"] == 200:
            working_sites.append((site, result))

    working_sites.sort(key=lambda item: item[1]["length"], reverse=True)

    for site, result in working_sites:
        print(f"{site} -> 200, {result['length']} octeți")

    failed_count = len(results) - len(working_sites)
    print(f"Site-uri reușite: {len(working_sites)}")
    print(f"Site-uri eșuate: {failed_count}")


def check_headers(url):
    """Verifică ce antete de securitate trimite site-ul."""
    try:
        response = requests.get(url, timeout=5)
    except requests.exceptions.RequestException:
        return {"status": None, "error": "Request failed"}

    response_header_names = []
    for name in response.headers:
        response_header_names.append(name.lower())

    present = []
    missing = []
    for header in SECURITY_HEADERS:
        if header.lower() in response_header_names:
            present.append(header)
        else:
            missing.append(header)

    score = len(present) * 100 // len(SECURITY_HEADERS)
    return {"present": present, "missing": missing, "score": score}


def retry_check(url, attempts=3):
    """Reîncearcă cererea dacă serverul dă o eroare sau conexiunea pică."""
    status = None
    last_error = None
    request_count = 0
    connection_errors = 0

    for _ in range(attempts):
        request_count += 1
        try:
            response = requests.get(url, timeout=5)
            status = response.status_code
            last_error = None
            if status < 500:
                return {"status": status, "attempts": request_count}
        except requests.exceptions.RequestException as error:
            connection_errors += 1
            last_error = str(error)

    result = {"status": status, "attempts": request_count}
    if request_count > 0 and connection_errors == request_count:
        result["error"] = last_error or "Request failed"
    return result


def test_helper_functions():
    print(build_url("example.com", "login"))
    print(build_url("example.com", "/login"))
    print(is_https("https://example.com"))
    print(is_https("http://example.com"))


if __name__ == "__main__":
    scan_sites()
