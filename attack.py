import requests
import threading
import random

url = "http://127.0.0.1:5000/login"

emails = ["lonewolf180705@gmail.com"]

user_agents = [
    "Mozilla/5.0",
    "Chrome/120.0",
    "Safari/537.36",
    "Edge/110.0",
    "AttackerBot/1.0"
]

def attack(thread_id):
    for i in range(20):
        headers = {
        "User-Agent": random.choice(user_agents),
        "X-Forwarded-For": "192.168.1.100"   # FIXED IP
}

        data = {
            "email": random.choice(emails),
            "password": "wrongpass"
        }

        try:
            r = requests.post(url, data=data, headers=headers)
            print(f"[Thread {thread_id}] Attempt {i+1} → {r.status_code}")
        except Exception as e:
            print(f"Error: {e}")

threads = []

# 5 parallel attackers
for i in range(5):
    t = threading.Thread(target=attack, args=(i,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("🔥 Attack Completed")