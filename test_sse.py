import requests

url = "http://localhost:8000/traps/stream"
print(f"⏳ Conectando a SSE {url} …")
with requests.get(url, stream=True) as resp:
    for line in resp.iter_lines():
        if line:
            print("📬 SSE:", line.decode())


