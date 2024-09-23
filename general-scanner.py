import requests
import re
import time
from termcolor import colored # type: ignore

# Sızıntı patternleri (Örnekler artırılabilir)
leak_patterns = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "ip_address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "phone_number": r"\+?\d{1,3}?[-.\s]?\(?\d{1,4}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "url": r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
    "api_key": r"AIza[0-9A-Za-z-_]{35}",
    "jwt_token": r"eyJ[a-zA-Z0-9-_=]+\.eyJ[a-zA-Z0-9-_=]+\.?[a-zA-Z0-9-_.+/=]*",
    "base64": r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
}

# Test edilecek payloadlar
payloads = [
    "' OR '1'='1' --", "<script>alert('XSS')</script>", "../../../../etc/passwd",
    # ... (Diğer payloadlar burada)
]

def test_vulnerability(url, payload):
    try:
        # Payload'ı URL'de deniyoruz
        response = requests.get(url, params={"input": payload}, timeout=10)
        # Response'da bir sızıntı veya zafiyet var mı kontrol ediyoruz
        if any(re.search(pattern, response.text) for pattern in leak_patterns.values()):
            return response, payload  # Zafiyet bulunursa response ve payload döndür
    except requests.exceptions.RequestException:
        pass
    return None, None

def scan_urls(file_name):
    try:
        with open(file_name, 'r') as f:
            urls = f.read().splitlines()

        print(colored("[+] Tarama başlatılıyor...", "yellow"))
        start_time = time.time()

        for url in urls:
            for payload in payloads:
                result, exploit_payload = test_vulnerability(url, payload)
                if result:
                    # Sömürülebilen zafiyet bulduğumuzda sonuçları yazdırıyoruz
                    exploit_details = f"""
                    [+] Sömürülen URL: {url}
                    [+] Kullanılan Payload: {exploit_payload}
                    [+] Zafiyet Nerede: {url} üzerindeki 'input' parametresinde
                    [+] Manuel Test Adımları: 
                        1. Tarayıcınızdan şu URL'yi ziyaret edin: {url}?input={exploit_payload}
                        2. Dönüş response'unu inceleyin.
                    [+] Zafiyetin Sebebi: Giriş doğrulaması eksik veya yetersiz.
                    [+] Çözüm Önerisi: Giriş verilerini filtreleyin, özel karakterleri sanitize edin ve WAF kullanarak ek güvenlik önlemleri alın.
                    """
                    print(colored(exploit_details, "green"))

        end_time = time.time()
        print(colored(f"Tarama tamamlandı! Geçen süre: {end_time - start_time:.2f} saniye", "blue"))

    except FileNotFoundError:
        print(colored(f"Hata: {file_name} dosyası bulunamadı.", "red"))

if __name__ == "__main__":
    dosya_adi = input(colored("Tarama yapılacak URL listesinin bulunduğu dosyanın adını girin: ", "yellow"))
    scan_urls(dosya_adi)
