import threading
import requests
import time
from collections import Counter

URL = "http://127.0.0.1"     # ← сюда свой serveo-адрес
THREADS = 100                    # ← потоков
REQUESTS_PER_THREAD = 10         # ← запросов на поток

results = []
lock = threading.Lock()

def worker(thread_id):
    for i in range(REQUESTS_PER_THREAD):
        try:
            r = requests.get(
                URL,
                timeout=10,
                allow_redirects=False,        # ← не идти по редиректу на /block
                headers={"User-Agent": f"FloodTest/{thread_id}"},
            )
            with lock:
                results.append(r.status_code)
        except Exception as e:
            with lock:
                results.append(f"ERR:{type(e).__name__}")

def main():
    print(f"URL: {URL}")
    print(f"Потоков: {THREADS}")
    print(f"Запросов на поток: {REQUESTS_PER_THREAD}")
    print(f"Всего: {THREADS * REQUESTS_PER_THREAD}")
    print("---")

    start = time.time()
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(THREADS)]
    for t in threads: t.start()
    for t in threads: t.join()
    elapsed = time.time() - start

    print(f"\nВремя: {elapsed:.2f} сек")
    print(f"RPS: {len(results) / elapsed:.1f}")
    print(f"Всего: {len(results)}")
    print("---")

    for code, count in sorted(Counter(results).items(), key=lambda x: str(x[0])):
        print(f"  {code}: {count}")

if __name__ == '__main__':
    main()
