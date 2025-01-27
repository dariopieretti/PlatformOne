from flask import Flask, render_template, request
import requests
import json
from msg_parser import MsOxMessage
import re
import hashlib
from docx import Document
import os
import extract_msg
import time
import base64
import datetime
from datetime import timezone, datetime as dt

app = Flask(__name__)

# Inserisci le tue API-KEY
API_KEY = ''
urlscan_api_key = ''
API_KEY_HA = ''
API_KEY_FS = ''
API_KEYAIP = ''
CONFIG_FILE = 'config.json.prod'

chiamateAPI_abuseIPDB = 0

abuseIPDB_categories = {
"1": "DNS Compromise",
"10": "Web Spam",
"11": "Email Spam",
"12": "Blog Spam",
"13": "VPN IP",
"14": "Port Scan",
"15": "Hacking",
"16": "SQL Injection",
"17": "Spoofing",
"18": "Brute-Force Credential",
"19": "Bad Web Bot",
"2": "DNS Poisoning",
"20": "Exploited Host",
"21": "Web App Attack",
"22": "SSH Secure Shell",
"23": "IoT Targeted",
"3": "Fraud Orders",
"4": "DDoS Attack",
"5": "FTP Brute-Force",
"6": "Ping of Death",
"7": "Phishing",
"8": "Fraud VoIP",
"9": "Open Proxy"
} 

def api_usage_vt(API_KEY):
    url = "https://www.virustotal.com/api/v3/users/"+ API_KEY
    headers = {"x-apikey": API_KEY}
    response_api = requests.get(url, headers=headers, verify=False)
    if response_api.status_code == 200:
        report_api_VT = response_api.json()
        api_hourly = report_api_VT.get('data', {}).get('attributes', {}).get('quotas', 'N/A').get('api_requests_hourly', 'N/A').get('used', 'N/A')
        api_daily = report_api_VT.get('data', {}).get('attributes', {}).get('quotas', 'N/A').get('api_requests_daily', 'N/A').get('used', 'N/A')
        api_monthly = report_api_VT.get('data', {}).get('attributes', {}).get('quotas', 'N/A').get('api_requests_monthly', 'N/A').get('used', 'N/A')
        return api_hourly, api_daily, api_monthly
    else:
        return None, None, None
    
def api_usage_urlscan(urlscan_api_key):
    headers = {'API-Key': urlscan_api_key, 'Content-Type': 'application/json'}
    response_api_US = requests.get("https://urlscan.io/user/quotas/", headers=headers, verify=False)
    if response_api_US.status_code == 200:
        report_api_US = response_api_US.json()
        api_hourly_US = report_api_US.get('limits', {}).get('public', {}).get('hour', 'N/A').get('used', 'N/A')
        api_daily_US = report_api_US.get('limits', {}).get('public', {}).get('day', 'N/A').get('used', 'N/A')
        return api_hourly_US, api_daily_US
    else:
        return None, None

def get_url_report(url):
    requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)
    urlscan_result = None  # Modifica qui per restituire None inizialmente
    screenshot_url = ''
    report_url = ''
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    #params = {'x-apikey': API_KEY, 'resource': url}
    header = {'x-apikey': API_KEY}
    response = requests.get('https://www.virustotal.com/api/v3/urls/'+url_id, headers=header, verify=False)
    if response.status_code == 200:
        report = response.json()
        if 'data' in report and 'Fortinet' in report['data']['attributes']['last_analysis_results']:
            fortinet_report = report['data']['attributes']['last_analysis_results']['Fortinet']['result']
            if fortinet_report.lower() in ['malware','phishing site']:  
                urlscan_result = effettua_analisi_urlscan(url)
                if urlscan_result and 'uuid' in urlscan_result:
                    uuid_value = urlscan_result['uuid']
                    #time.sleep(5)
                    screenshot_url = ottieni_screenshot_urlscan(uuid_value)
                else:
                    uuid_value = "N/A"

        else:
            fortinet_report = "Report Fortinet non disponibile"
            uuid_value = "N/A"
        
        # Verifica se la scansione è stata effettuata
        timestamp = report.get('data', {}).get('attributes', {}).get('last_analysis_date', 'N/A')
        if timestamp != 'N/A':
            scan_date = datetime.datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        else:
            scan_date = 'N/A'

        # Restituisci positivi, totali e urlscan_result
        positives = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 'N/A')
        total = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 'N/A')

        # Check se report_url è disponibile
        report_url = report.get('permalink', 'N/A')

        return fortinet_report, scan_date, positives, total, urlscan_result, screenshot_url, report_url
    else:
        return None, None, None, None, None, None, None
    
def ottieni_screenshot_urlscan(uuid_value):
    flag = True
    headers = {'API-Key': urlscan_api_key, 'Content-Type': 'application/json'}
    response=requests.get("https://urlscan.io/api/v1/result/"+ uuid_value, headers=headers, verify=False)
    if response.status_code != 200:
        while flag:
            response=requests.get("https://urlscan.io/api/v1/result/"+ uuid_value, headers=headers, verify=False)
            if response.status_code == 200:
                flag = False
            else:
                time.sleep(2)
    screenshot_url = f"https://urlscan.io/screenshots/{uuid_value}.png"
    return screenshot_url
    
def effettua_analisi_urlscan(url):
    requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)
    #urlscan_api_url = f'https://urlscan.io/api/v1/scan'
    headers = {'API-Key': urlscan_api_key, 'Content-Type': 'application/json'}
    data = {'url': url}
    response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return {}

def get_hash_report(API_KEY, hash_value):
    requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)
    url_vt = 'https://www.virustotal.com/api/v3/files/'+ hash_value
    params_vt = {'x-apikey': API_KEY}
    #, 'resource': hash_value}

    # Chiamata a VirusTotal
    response_vt = requests.get(url_vt, headers=params_vt, verify=False)
    if response_vt.status_code == 200:
        report_vt = response_vt.json()
        timestamp = report_vt.get('data', {}).get('attributes', {}).get('last_analysis_date', 'N/A')
        if timestamp != 'N/A':
            scan_date_hash = datetime.datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        else:
            scan_date_hash = 'N/A'
        symantec_verdict = report_vt.get('data', {}).get('attributes', {}).get('last_analysis_results', {}).get('Symantec', {}).get('category', 'N/A')
        fortinet_verdict = report_vt.get('data', {}).get('attributes', {}).get('last_analysis_results', {}).get('Fortinet', {}).get('category', 'N/A')
        trend_micro_verdict = report_vt.get('data', {}).get('attributes', {}).get('last_analysis_results', {}).get('TrendMicro', {}).get('category', 'N/A')
        positives_hash = report_vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', 'N/A').get('malicious', 'N/A')
        total_hash = report_vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', 'N/A').get('harmless', 'N/A')
        name_file = report_vt.get('data', {}).get('attributes', {}).get('names', ['N/A'])[0]
        file_type = report_vt.get('data', {}).get('attributes', {}).get('type_description', 'N/A')

        # Chiamata a FileScan
        url_fs = 'https://www.filescan.io/api/reputation/hash'
        params_fs = {'sha256': hash_value}
        headers_fs = {'X-Api-Key': API_KEY_FS}
        response_fs = requests.get(url_fs, headers=headers_fs, params=params_fs, verify=False)
        if response_fs.status_code == 200:
            report_fs = response_fs.json()
            filescan_reports = report_fs.get('filescan_reports', [])
            if filescan_reports:
                reputation_fs = filescan_reports[0].get('verdict', 'N/A')
                scan_date_fs = filescan_reports[0].get('report_date', 'N/A')
            else:
                reputation_fs = 'N/A'
                scan_date_fs = 'N/A'

        # Chiamata a Hybrid Analysis
        url_HA = 'https://www.hybrid-analysis.com/api/v2/overview/'
        #path = {{ hash_value }}
        url_total_HA = f"{url_HA}{hash_value}"
        headers = { 'accept':'application/json', 'api-key': API_KEY_HA}

        response_HA = requests.get(url_total_HA, headers=headers, verify=False)
        if response_HA.status_code == 200:
            hash_reputation_HA = response_HA.json()
            reputation_HA = hash_reputation_HA.get('verdict', 'N/A')
            threat_score_HA = hash_reputation_HA.get('threat_score', 'N/A')
            if threat_score_HA != 'N/A':
                threat_score_HA = str(threat_score_HA) + " / 100"
            type_HA = hash_reputation_HA.get('type', 'N/A')
            size_HA = hash_reputation_HA.get('size', 'N/A')
            scannerHA_Crowd = hash_reputation_HA.get('scanners', [])[0].get('status', 'N/A')
            scannerHA_Meta = hash_reputation_HA.get('scanners', [])[1].get('status', 'N/A')
        else:
            reputation_HA = 'N/A'
            threat_score_HA = 'N/A'
            type_HA = 'N/A'
            size_HA = 'N/A'
            scannerHA_Crowd = 'N/A'
            scannerHA_Meta = 'N/A'

        # Chiamata a MalwareBazaar
        MB_result = cerca_hash_malwarebazar(hash_value)

        return scan_date_hash, symantec_verdict, positives_hash, total_hash, reputation_fs, scan_date_fs, reputation_HA, threat_score_HA, type_HA, size_HA, scannerHA_Crowd, scannerHA_Meta, fortinet_verdict, trend_micro_verdict, MB_result, name_file, file_type
    else:
        return None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None

def cerca_hash_malwarebazar(hash_value):
    requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)
    url = 'https://mb-api.abuse.ch/api/v1/'
    data = {'query': 'get_info', 'hash': hash_value}
    response = requests.post(url, data=data, verify=False)
    
    if response.status_code == 200:
        result_MB = response.json()
        if 'query_status' in result_MB and result_MB['query_status'] == 'ok':
            for data_item in result_MB['data']:
                Nome_file_MB = data_item.get('file_name', 'N/A')
                Yoroi_MB = data_item.get('vendor_intel', {}).get('YOROI_YOMI', {}).get('detection', 'N/A')
                CERT_PL_MWDB_MB = data_item.get('vendor_intel', {}).get('CERT-PL_MWDB', {}).get('detection', 'N/A')
                Cape_MB = data_item.get('vendor_intel', {}).get('CAPE', {}).get('0', {}).get('detection', 'N/A')
                Spamhaus_MB =", ".join(d.get('detection', 'N/A') for d in data_item.get('vendor_intel', {}).get('Spamhaus_HBL', []))
                InQuest_MB = data_item.get('vendor_intel', {}).get('InQuest', {}).get('verdict', 'N/A')

        else:
            Nome_file_MB = 'N/A'
            Yoroi_MB = 'N/A'
            CERT_PL_MWDB_MB = 'N/A'
            Cape_MB = 'N/A'
            Spamhaus_MB = 'N/A'
            InQuest_MB = 'N/A'
            
        return Nome_file_MB, Yoroi_MB, CERT_PL_MWDB_MB, Cape_MB, Spamhaus_MB, InQuest_MB
    else:
        return None, None, None, None, None, None

def analisi_email(msg_file):
    # Verifica se il file ha l'estensione .msg
    if not msg_file.filename.endswith('.msg'):
        return None, "Il file fornito non è un file .msg."

    # Utilizza extract_msg per estrarre i dati dal file .msg
    try:
        msg = extract_msg.Message(msg_file)
    except extract_msg.exceptions.InvalidFileFormatError:
        return None, "Il file fornito non è nel formato corretto."

    # Ottieni informazioni dal messaggio
    corpo_messaggio = msg.body
    mittente = msg.sender
    destinatario = msg.to
    cc = msg.cc
    oggetto = msg.subject

    results = []
    report_urls_allegato = []

    # Crea la cartella "allegati" se non esiste già
    folder_path = os.path.join(os.getcwd(), 'allegati')
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    # Estrai e salva gli allegati
    allegati = []
    for attachment in msg.attachments:
        # Verifica se l'allegato è un'immagine .png
        if not attachment.longFilename.lower().endswith('.png'):
            allegato_file_path = os.path.join('allegati', attachment.longFilename)
            with open(allegato_file_path, 'wb') as f:
                f.write(attachment.data)
            # Calcola l'hash dell'allegato
            hash_value = calcola_hash_allegato(allegato_file_path)
            # Ottieni il report sull'hash dell'allegato
            scan_date_hash, symantec_verdict, positives_hash, total_hash, _, _, _, _, type_HA, _, _, _, fortinet_verdict, trend_micro_verdict, MB_result, name_file, file_type = get_hash_report(API_KEY, hash_value)
            # Trova le URL nell'allegato
            urls_in_allegato, report_urls_allegato = trova_url_nell_allegato(allegato_file_path)
            allegati.append({
                'nome_allegato': attachment.longFilename,
                'percorso_allegato': allegato_file_path,
                'hash_allegato': hash_value,
                'scan_date_hash': scan_date_hash,
                'symantec_verdict': symantec_verdict,
                'fortinet_verdict': fortinet_verdict,
                'trend_micro_verdict': trend_micro_verdict,
                'positives_hash': positives_hash,
                'total_hash': total_hash,
                'type_HA': type_HA,
                'urls': urls_in_allegato,  # Aggiungi le URL trovate nell'allegato
                'Malware Bazaar' : MB_result,
                'name_file': name_file,
                'file_type' : file_type
            })
            
            # Elimina l'allegato dalla cartella dopo l'analisi
            os.remove(allegato_file_path)

    # Trova URL nel corpo del messaggio
    pattern_url = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+|www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    url_trovate = pattern_url.findall(corpo_messaggio)
    
    for url in url_trovate:
        url = url.replace('>', '')
        fortinet_result, scan_date, positives, total, _, _, report_url = get_url_report(url)
        results.append({
            'url': url,
            'fortinet_result': fortinet_result,
            'scan_date': scan_date,
            'positives': positives,
            'total': total,
            'report_url': report_url
        }) 

    # Restituisci tutti i valori correttamente
    return results, allegati, mittente, destinatario, cc, oggetto, corpo_messaggio, report_urls_allegato

def trova_url_nell_allegato(allegato_path):
    urls = []
    with open(allegato_path, 'rb') as file:
        content = file.read().decode(errors='ignore')
        # Utilizza un'espressione regolare per trovare le URL nel contenuto dell'allegato
        pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+|www\.(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        urls = pattern.findall(content)
        
    # Elimina le URL che contengono 'adobe'
    urls = [url for url in urls if 'adobe' not in url.lower() and 'w3.org' not in url.lower() and 'purl.org' not in url.lower()]

    if allegato_path.endswith('.docx'):
        text = estrai_testo_da_docx(allegato_path)
        # Aggiungi le URL trovate nel testo del documento DOCX
        pattern_url = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+|www\.(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        urls_in_docx = pattern_url.findall(text)
        urls.extend(urls_in_docx)

    # Ottieni il report per ciascuna URL trovata
    report_urls_allegato = []
    for url in urls:
        fortinet_result, scan_date, positives, total, _, _, report_url = get_url_report(url)
        report_urls_allegato.append({
            'url': url,
            'fortinet_result': fortinet_result,
            'scan_date': scan_date,
            'positives': positives,
            'total': total,
            'report_url': report_url
        })

    return urls, report_urls_allegato

def estrai_testo_da_docx(file_path):
    text = ""
    doc = Document(file_path)
    for paragraph in doc.paragraphs:
        text += paragraph.text
    return text

def calcola_hash_allegato(file_path):
    with open(file_path, 'rb') as f:
        hash_obj = hashlib.sha256()
        hash_obj.update(f.read())
        hash_value = hash_obj.hexdigest()
    
    return hash_value

def get_report_IP(ip):
    global chiamateAPI_abuseIPDB
    # Controlla se è un nuovo giorno
    data_corrente = datetime.datetime.now().date()
    if data_corrente != getattr(get_report_IP, 'ultima_data_controllata', None):
        chiamateAPI_abuseIPDB = 0  # Reimposta il contatore
        get_report_IP.ultima_data_controllata = data_corrente  # Aggiorna l'ultima data controllata
    
    chiamateAPI_abuseIPDB += 1
    requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)
    header = {'x-apikey': API_KEY}
    response_vt = requests.get('https://www.virustotal.com/api/v3/ip_addresses/'+ ip, headers=header, verify=False)

    if response_vt.status_code == 200:
        report_ip_vt = response_vt.json()
        Forcepoint_verdict_ip = report_ip_vt.get('data', {}).get('attributes', {}).get('last_analysis_results', {}).get('Forcepoint ThreatSeeker', {}).get('category', 'N/A')
        Fortinet_verdict_ip = report_ip_vt.get('data', {}).get('attributes', {}).get('last_analysis_results', {}).get('Fortinet', {}).get('category', 'N/A')
        total_harmless_verdict_ip = report_ip_vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 'N/A')
        total_malicious_verdict_ip = report_ip_vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 'N/A')
        cn_ip = report_ip_vt.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('subject', {}).get('CN', 'N/A')
        name_ip = report_ip_vt.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('issuer', {}).get('O', 'N/A')
        country_ip = report_ip_vt.get('data', {}).get('attributes', {}).get('country', 'N/A')

    # Chiamata ad AbuseIPDB
    requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)
    url_abuseipdb = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip, 'maxAgeInDays': '365', 'verbose': True}
    headers = {'Accept': 'application/json', 'Key': API_KEYAIP}
    
    responseAIP = requests.request(method='GET', url=url_abuseipdb, headers=headers, params=querystring, verify=False)

    if responseAIP.status_code == 200:
        report_ip_AIP = responseAIP.json()
        AIP_score = report_ip_AIP.get('data', {}).get('abuseConfidenceScore', 'N/A')
        AIP_usage = report_ip_AIP.get('data', {}).get('usageType', 'N/A')
        AIP_isp = report_ip_AIP.get('data', {}).get('isp', 'N/A')
        AIP_isTor = report_ip_AIP.get('data', {}).get('isTor', 'N/A')
        AIP_totalReport = report_ip_AIP.get('data', {}).get('totalReports', 'N/A')
        # Estrai le categorie
        reports = report_ip_AIP.get('data', {}).get('reports', [])
        date_format='%Y-%m-%d'
        if reports:
            report_categories = {}
            for x in reports:
                cat_abuse=[]
                for xx in x.get('categories', []):
                    cat_abuse.append(abuseIPDB_categories[str(xx)])
                s=', '.join(cat_abuse)
                parsed_date = dt.strptime(x.get('reportedAt', []).split('T')[0], date_format)
                formatted_date = parsed_date.strftime('%d/%m/%Y')
                report_categories[formatted_date] = s
        else:
            report_categories = []
        
        return Forcepoint_verdict_ip, Fortinet_verdict_ip, total_harmless_verdict_ip, total_malicious_verdict_ip, cn_ip, name_ip, country_ip, AIP_score, AIP_usage, AIP_isp, AIP_isTor, AIP_totalReport, report_categories
    else:
        return None, None, None, None, None, None, None, None, None, None, None, None, None, None


@app.route('/')
def index():
    api_hourly, api_daily, api_monthly = api_usage_vt(API_KEY)
    api_hourly_US, api_daily_US = api_usage_urlscan(urlscan_api_key)
    return render_template('index.html', api_hourly=api_hourly, api_daily=api_daily, api_monthly=api_monthly, api_hourly_US=api_hourly_US, api_daily_US=api_daily_US, API_KEY=API_KEY,
                           API_KEY_HA=API_KEY_HA, urlscan_api_key=urlscan_api_key, API_KEY_FS=API_KEY_FS, API_KEYAIP=API_KEYAIP, chiamateAPI_abuseIPDB=chiamateAPI_abuseIPDB)


@app.route('/get_report', methods=['POST'])
def get_report():
    url = request.form['url']
    fortinet_result, scan_date, positives, total, urlscan_result, screenshot_url, report_url = get_url_report(url)
    virus_total_report_url = "https://www.virustotal.com/gui/domain/" + url + "/detection"
    return render_template('report.html', fortinet_result=fortinet_result, scan_date=scan_date, positives=positives, total=total, url=url, urlscan_result=urlscan_result, screenshot_url=screenshot_url, virus_total_report_url=virus_total_report_url)

@app.route('/get_hash_report', methods=['POST'])
def get_hash_report_route():
    hash_value = request.form['hash']
    scan_date_hash, symantec_verdict, positives_hash, total_hash, reputation_fs, scan_date_fs, reputation_HA, threat_score_HA, type_HA, size_HA, scannerHA_Crowd, scannerHA_Meta, fortinet_verdict, trend_micro_verdict, MB_result, name_file, file_type = get_hash_report(API_KEY, hash_value)
    report_hash_vt = "https://www.virustotal.com/gui/file/" + hash_value + "/detection"
    return render_template('reportHash.html', hash=hash_value, scan_date_hash=scan_date_hash, symantec_verdict=symantec_verdict, 
                           positives_hash=positives_hash, total_hash=total_hash, report_hash_vt=report_hash_vt, reputation_fs=reputation_fs, 
                           scan_date_fs=scan_date_fs, reputation_HA=reputation_HA, threat_score_HA=threat_score_HA, type_HA=type_HA, 
                           size_HA=size_HA, scannerHA_Crowd=scannerHA_Crowd, scannerHA_Meta=scannerHA_Meta, fortinet_verdict=fortinet_verdict, 
                           trend_micro_verdict=trend_micro_verdict, MB_result=MB_result, name_file=name_file, file_type=file_type)

@app.route('/analyze_email', methods=['POST'])
def analyze_email():
    email_file = request.files.get('email')
    if email_file is None or email_file.filename == '':
        return "Nessun file email è stato fornito", 400
    results, allegati, mittente, destinatario, cc, oggetto, corpo_messaggio, report_urls_allegato = analisi_email(email_file)
    return render_template('reportEmail.html', url_results = results, allegati = allegati, mittente = mittente, destinatario = destinatario, cc = cc, oggetto = oggetto, corpo_messaggio=corpo_messaggio, report_urls_allegato=report_urls_allegato)  

@app.route('/playbook_phishing_page')
def phishing_page():
    return render_template('playbook_phishing.html')

@app.route('/template_email_page')
def template_email_page():
    return render_template('templatesEmail.html')

@app.route('/get_report_ip', methods=['POST'])
def get_report_ip():
    ip = request.form['ip']
    Forcepoint_verdict_ip, Fortinet_verdict_ip, total_harmless_verdict_ip, total_malicious_verdict_ip, cn_ip, name_ip, country_ip, AIP_score, AIP_usage, AIP_isp, AIP_isTor, AIP_totalReport, report_categories = get_report_IP(ip)
    
    return render_template('report_ip.html',ip=ip, Forcepoint_verdict_ip=Forcepoint_verdict_ip, Fortinet_verdict_ip=Fortinet_verdict_ip, total_harmless_verdict_ip=total_harmless_verdict_ip, 
                           total_malicious_verdict_ip=total_malicious_verdict_ip, cn_ip=cn_ip, name_ip=name_ip, country_ip=country_ip, AIP_score=AIP_score, AIP_usage=AIP_usage,
                           AIP_isp=AIP_isp, AIP_isTor=AIP_isTor, AIP_totalReport=AIP_totalReport, report_categories=report_categories)

@app.route('/api_key_page')
def api_key_page():
    api_hourly, api_daily, api_monthly = api_usage_vt(API_KEY)
    api_hourly_US, api_daily_US = api_usage_urlscan(urlscan_api_key)
    return render_template('api_key_page.html', API_KEY=API_KEY, API_KEY_HA=API_KEY_HA, API_KEY_FS=API_KEY_FS, urlscan_api_key=urlscan_api_key, API_KEYAIP=API_KEYAIP,
                           api_hourly=api_hourly, api_daily=api_daily, api_monthly=api_monthly, api_hourly_US=api_hourly_US, api_daily_US=api_daily_US,chiamateAPI_abuseIPDB=chiamateAPI_abuseIPDB)

@app.route('/playbooks&templates')
def playbooks_templates():  
    return render_template('playbooks&templates.html')

@app.route('/leaks')
def leaks_templates():  
    return render_template('leaked_mail.html')

if __name__ == '__main__':
    with open(CONFIG_FILE, 'r') as r_f:
        config = json.load(r_f)
        API_KEY  = config['API_KEY']
        API_KEY_HA  = config['API_KEY_HA']
        API_KEY_FS  = config['API_KEY_FS']
        urlscan_api_key  = config['urlscan_api_key']
        API_KEYAIP = config ['API_KEYAIP']
    app.run(debug=True, host= '0.0.0.0')
