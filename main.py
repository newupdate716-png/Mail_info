from flask import Flask, request, jsonify
import socket
import ssl
import whois
import dns.resolver
import requests
import os

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({
        "message": "Welcome to Mail Info API",
        "usage": "/info?mail=example@gmail.com"
    })


@app.route('/info', methods=['GET'])
def mail_info():
    email = request.args.get('mail')
    if not email:
        return jsonify({"error": "Please provide ?mail= parameter"}), 400

    try:
        domain = email.split("@")[-1].strip().lower()

        # --- MX RECORDS ---
        try:
            mx_records = [str(r.exchange).rstrip('.') for r in dns.resolver.resolve(domain, "MX")]
        except Exception:
            mx_records = ["No record found"]

        # --- DOMAIN IP ---
        try:
            ip_addr = socket.gethostbyname(domain)
        except Exception:
            ip_addr = "Unknown"

        # --- SSL ISSUER ---
        ssl_issuer = "Unknown"
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    ssl_issuer = issuer.get("organizationName", "Unknown")
        except Exception:
            pass

        # --- WHOIS INFO ---
        try:
            w = whois.whois(domain)
            registrar = w.registrar or "Unknown"
            creation_date = str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date)
            expiration_date = str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date)
        except Exception:
            registrar = creation_date = expiration_date = "Unknown"

        # --- ISP + LOCATION ---
        isp = "Unknown"
        location = "Unknown"
        if ip_addr != "Unknown":
            try:
                ipinfo = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=6).json()
                isp = ipinfo.get("isp", "Unknown")
                location = f"{ipinfo.get('city', 'Unknown')}, {ipinfo.get('country', 'Unknown')}"
            except Exception:
                pass

        # --- DISPOSABLE DOMAIN CHECK ---
        disposable_domains = ["tempmail.com", "10minutemail.com", "yopmail.com", "guerrillamail.com"]
        disposable = "Yes" if domain in disposable_domains else "No"

        # --- BREACH CHECK ---
        try:
            hibp = requests.get(
                f"https://haveibeenpwned.com/unifiedsearch/{email}",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10
            )
            if hibp.status_code == 200:
                data = hibp.json()
                breaches = [b["Name"] for b in data.get("Breaches", [])]
            elif hibp.status_code == 404:
                breaches = []
            else:
                breaches = ["Error fetching data"]
        except Exception:
            breaches = ["Error fetching data"]

        # --- RESPONSE ---
        return jsonify({
            "Email": email,
            "Domain": domain,
            "Provider": "Google Gmail" if "gmail" in domain else "Unknown",
            "MX Records": mx_records,
            "Domain IP": ip_addr,
            "Server Location": location,
            "ISP": isp,
            "Registrar": registrar,
            "Creation Date": creation_date,
            "Expiration Date": expiration_date,
            "SSL Issuer": ssl_issuer,
            "Disposable": disposable,
            "Breaches Found": breaches
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
    
    
    
# CREDIT: @sakib01994 
# CREDIT: @sakib01994 
# CREDIT: @sakib01994 
