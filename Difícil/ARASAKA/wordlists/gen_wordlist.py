#!/usr/bin/env python3
"""Genera la wordlist temática de ARASAKA para el pivote SSH."""
from itertools import product

users = ["netrunner", "takemura"]

base = [
    # comunes
    "admin", "admin123", "administrator", "root", "toor", "password", "password123",
    "Password123", "P@ssw0rd", "P@ssw0rd123", "letmein", "welcome", "changeme",
    "secret", "qwerty", "qwerty123", "123456", "12345678", "123456789", "abc123",
    "ubuntu", "kali", "debian", "jenkins", "jenkins123", "test", "test123", "guest",
    "user", "user123", "login", "master", "server", "nightcity", "NightCity",
    "nightcity2077", "NightCity2077", "N1ghtC1ty", "N1ghtC1ty2077", "cyberpunk",
    "Cyberpunk", "cyberpunk2077", "Cyberpunk2077", "2077", "2026", "2020",
    "nightcity2020", "NightCity2020", "arasaka", "Arasaka", "arasaka123",
    "Arasaka123", "arasaka2026", "Arasaka2026", "arasaka2077", "Arasaka2077",
    # netrunner
    "netrunner", "Netrunner", "NetRunner", "netrunner123", "Netrunner123",
    "n3trunn3r", "N3trunn3r", "netrunner2077", "Netrunner2077", "netrunner2026",
    "alt", "Alt", "altcunningham", "AltCunningham", "cunningham", "Cunningham",
    "spider", "Spider", "spidermurphy", "SpiderMurphy", "murphy", "Murphy",
    "blackwall", "Blackwall", "blackwall2077", "quickhack", "Quickhack",
    "daemon", "Daemon", "cyberdeck", "Cyberdeck", "netwatch", "Netwatch",
    "ice", "ICE", "braindance", "Braindance", "relic", "Relic", "soulkiller",
    "Soulkiller", "mikoshi", "Mikoshi",
    # takemura
    "takemura", "Takemura", "goro", "Goro", "gorotakemura", "GoroTakemura",
    "goro123", "Goro123", "takemura123", "Takemura123", "bodyguard", "Bodyguard",
    "corpo", "Corpo", "saburo", "Saburo", "hanako", "Hanako", "yorinobu",
    "Yorinobu", "arv0", "Arv0",
    # otros personajes
    "johnny", "Johnny", "silverhand", "Silverhand", "JohnnySilverhand",
    "samurai", "Samurai", "rockerboy", "Rockerboy", "neverfadeaway",
    "NeverFadeAway", "chippin", "Chippin", "wakeup", "WakeUp", "wakeupsamurai",
    "blackdog", "BlackDog", "kerry", "Kerry", "eurodyne", "Eurodyne", "rogue",
    "Rogue", "amendiares", "Amendiares", "adam", "Adam", "smasher", "Smasher",
    "adamsmasher", "AdamSmasher", "jackie", "Jackie", "welles", "Welles",
    "misty", "Misty", "vik", "Viktor", "panam", "Panam", "judy", "Judy",
]

suffixes = ["", "123", "1234", "2026", "2077", "!", "@", "2026!", "2077!"]
words = []
for w in base:
    words.append(w)
    for s in suffixes:
        words.append(w + s)
    words.append(w.capitalize())
    words.append(w.upper())

seen = set()
with open("wordlists/arasaka_passwords.txt", "w") as f:
    for w in words:
        if w not in seen:
            seen.add(w)
            f.write(w + "\n")
with open("wordlists/arasaka_users.txt", "w") as f:
    f.write("\n".join(users) + "\n")
print(f"usuarios: {len(users)}  contraseñas: {len(seen)}")
