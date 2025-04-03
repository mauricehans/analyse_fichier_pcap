import requests
import os
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get API key directly from environment
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', 'demo_key')
logger.info(f"Using VirusTotal API key: {'demo_key' if VIRUSTOTAL_API_KEY == 'demo_key' else '****'}")

def check_ip_reputation(ip):
    # Cache simple en mémoire pour les résultats récents
    if hasattr(check_ip_reputation, 'cache'):
        if ip in check_ip_reputation.cache:
            return check_ip_reputation.cache[ip]
    else:
        check_ip_reputation.cache = {}

    try:
        # Réduire le délai entre les requêtes
        time.sleep(0.2)

        url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': VIRUSTOTAL_API_KEY, 'ip': ip}
        
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        
        # Ajuster les seuils de détection
        detected_urls = data.get('detected_urls', [])
        detected_samples = data.get('detected_communicating_samples', [])
        
        # Calculer le score de menace avec des seuils plus bas
        threat_score = 0
        
        # Points pour les URLs détectées
        if detected_urls:
            threat_score += sum(url.get('positives', 0) for url in detected_urls)
        
        # Points pour les échantillons détectés
        if detected_samples:
            threat_score += len(detected_samples)
            
        # Nouveaux seuils de menace
        if threat_score > 5:
            threat_level = 'High'
        elif threat_score > 2:
            threat_level = 'Medium'
        elif threat_score > 0:
            threat_level = 'Low'
        else:
            threat_level = 'Unknown'
            
        logger.info(f"IP {ip} analysis - Score: {threat_score}, Level: {threat_level}")
            
        result = {
            'ip': ip,
            'threat_level': threat_level,
            'detections': threat_score,
            'details': {
                'detected_urls': len(detected_urls),
                'detected_samples': len(detected_samples),
                'country': data.get('country', 'Unknown'),
                'as_owner': data.get('as_owner', 'Unknown'),
                'threat_score': threat_score
            }
        }
        
        # Mettre en cache le résultat
        check_ip_reputation.cache[ip] = result
        return result
        
    except Exception as e:
        logger.error(f"Error checking IP {ip}: {e}")
        return {
            'ip': ip,
            'threat_level': 'Unknown',
            'detections': 0,
            'error': str(e)
        }
