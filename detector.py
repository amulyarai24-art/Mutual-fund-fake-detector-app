import os
import re
import zipfile
import json
from androguard.core.bytecodes.apk import APK
from PIL import Image
import imagehash
from rapidfuzz import fuzz
import subprocess

SUSPICIOUS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
}

RED_FLAG_KEYWORDS = [
    "guarantee", "guaranteed", "fixed return",
    "15% return", "daily income", "vip", "refer and earn"
]

UPI_REGEX = re.compile(r"[a-zA-Z0-9.\-_]+@[\w]+", re.IGNORECASE)
URL_REGEX = re.compile(r"https?://[^\s'\"]+")

def load_whitelist(path="whitelist.json"):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

WHITELIST = load_whitelist()

def get_cert_fingerprint(apk_path):
    try:
        out = subprocess.check_output(
            ["apksigner", "verify", "--print-certs", apk_path], text=True
        )
        for line in out.splitlines():
            if "SHA-256 digest" in line:
                return line.split(": ")[1].strip()
    except:
        return None

def extract_strings_from_apk(apk_path):
    strings = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if name.lower().endswith((".xml", ".dex", ".arsc", ".txt", ".json")):
                    try:
                        data = z.read(name).decode("latin-1", errors="ignore")
                        strings.append(data)
                    except:
                        pass
    except:
        pass
    return "\n".join(strings)

def detect_fake(apk_path):
    apk = APK(apk_path)
    meta = {
        "app_name": apk.get_app_name(),
        "package": apk.get_package(),
        "permissions": apk.get_permissions() or []
    }

    icon_phash = None
    icon_path = apk.get_app_icon()
    if icon_path:
        icon_bytes = apk.get_file(icon_path)
        if icon_bytes:
            with open("temp_icon.png", "wb") as f:
                f.write(icon_bytes)
            try:
                icon_phash = imagehash.phash(Image.open("temp_icon.png"))
            except:
                icon_phash = None
            try:
                os.remove("temp_icon.png")
            except:
                pass

    bigtext = extract_strings_from_apk(apk_path)
    cert = get_cert_fingerprint(apk_path)

    score = 0
    evidence = []

    for w in WHITELIST:
        title_sim = fuzz.ratio((meta["app_name"] or "").lower(), (w["name"]).lower())
        if title_sim >= 80:
            score += 20
            evidence.append(f"Title similar to {w.get('name')} ({title_sim}%)")

        pkg_sim = fuzz.ratio((meta.get("package") or "").lower(), (w.get("package") or "").lower())
        if pkg_sim >= 90:
            score += 20
            evidence.append(f"Package similar to {w.get('package')}")

        if icon_phash and w.get("icon") and os.path.exists(w.get("icon")):
            try:
                wh_hash = imagehash.phash(Image.open(w.get("icon")))
                dist = icon_phash - wh_hash
                if dist <= 10:
                    score += 40
                    evidence.append(f"Icon similar to {w.get('name')} (distance={dist})")
            except:
                pass

        if cert and w.get("cert"):
            if meta.get("package") == w.get("package") and cert != w.get("cert"):
                score += 40
                evidence.append(f"Certificate mismatch for {w.get('name')}")

    bad_perms = [p for p in meta.get("permissions", []) if p in SUSPICIOUS_PERMS]
    if bad_perms:
        score += 20
        evidence.append(f"Suspicious permissions: {bad_perms}")

    found_words = [k for k in RED_FLAG_KEYWORDS if k in bigtext.lower()]
    if found_words:
        score += 20
        evidence.append(f"Scam keywords: {found_words}")

    upis = UPI_REGEX.findall(bigtext)
    if upis:
        score += 30
        evidence.append(f"UPI-like strings found: {upis[:5]}")

    urls = URL_REGEX.findall(bigtext)
    bad_urls = [u for u in urls if not any(d.lower() in u.lower() for d in [w.get('package','') for w in WHITELIST])]
    if bad_urls:
        score += 20
        evidence.append(f"Suspicious URLs: {bad_urls[:5]}")

    if score >= 60:
        verdict = "HIGH RISK - Likely FAKE"
    elif score >= 40:
        verdict = "MEDIUM RISK - Suspicious"
    else:
        verdict = "LOW RISK - Probably Safe"

    return {
        "app_name": meta.get("app_name"),
        "package": meta.get("package"),
        "score": score,
        "verdict": verdict,
        "evidence": evidence
    }

if __name__ == '__main__':
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python detector.py path/to/app.apk")
    else:
        print(json.dumps(detect_fake(sys.argv[1]), indent=2))
