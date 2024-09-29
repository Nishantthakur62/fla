from flask import Flask, render_template, request, jsonify
import requests
import pycountry
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

api_keys = [
    'bf17cc53c830f44e9c186c044ac43d37d114974280d4eaf088d60ee3e57585a5',
    '6d740c63034dad9ab24a4a9b85cd842bda40383d66890b52fb70cf9707b4bbd4',
    '840002bf8d2c77c72a984c021c01c114cafb20b3e9546a18dbd086880d1a48a3',
    '5ad66558638b424bc101d5e2125647a7f709b3b91be4749e54dd603396a4245b'
]

key_index = 0

def fetch_api_key():
    global key_index
    api_key = api_keys[key_index]
    key_index = (key_index + 1) % len(api_keys)
    return api_key

def get_country_name(country_code):
    try:
        return pycountry.countries.get(alpha_2=country_code).name
    except LookupError:
        return country_code  # Return the code if not found

def analyze_ip(ip_address):
    try:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {'x-apikey': fetch_api_key()}
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            raise requests.exceptions.RequestException(f"Failed with status code {response.status_code}")

        data = response.json()
        if 'data' not in data:
            raise ValueError("Unexpected response structure")

        attributes = data['data']['attributes']
        isp = attributes.get('as_owner')
        country_code = attributes.get('country')
        country_name = get_country_name(country_code)
        stats = attributes.get('last_analysis_stats')

        malicious_count = stats.get('malicious', 0)
        total_count = sum(stats.values())

        community_score = f"Blacklisted {malicious_count}/{total_count}"

        return {
            'ISP': isp,
            'Country Code': country_code,
            'Country Name': country_name,
            'Community Score': community_score
        }

    except Exception as e:
        print(f"Error for IP {ip_address}: {e}")
        return None

def is_valid_ip(ip):
    """Validate if the input is a valid IP address."""
    ip_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return ip_regex.match(ip) is not None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        ip_addresses = request.form.get('ip_addresses').strip().splitlines()
        results = {}
        invalid_ips = []

        # Validate IP addresses and strip whitespace
        for ip in ip_addresses:
            cleaned_ip = ip.strip()
            if cleaned_ip and is_valid_ip(cleaned_ip):
                results[cleaned_ip] = None  # Prepare for results
            elif cleaned_ip:  # Only add non-empty strings
                invalid_ips.append(cleaned_ip)

        if invalid_ips:
            return jsonify({"error": "Invalid IP addresses detected: " + ", ".join(invalid_ips)}), 400

        # Process IPs using ThreadPoolExecutor
        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(analyze_ip, ip): ip for ip in results.keys()}
            for future in as_completed(futures):
                ip_address = futures[future]
                result = future.result()
                results[ip_address] = result

        # Prepare output maintaining input order, including duplicates
        ordered_output = {ip: results[ip] for ip in ip_addresses if ip.strip() in results}

        return jsonify(ordered_output)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
