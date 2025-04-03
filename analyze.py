import logging
from scapy.all import rdpcap, IP
from collections import Counter
import json
from virustotal import check_ip_reputation
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logger = logging.getLogger(__name__)

def analyze_pcap(filepath):
    logger.info(f"Starting analysis of {filepath}")
    packets = rdpcap(filepath)
    
    # Initialize analysis results
    results = {
        'total_packets': len(packets),
        'ip_sources': Counter(),
        'ip_destinations': Counter(),
        'protocols': Counter(),
        'suspicious_ips': [],
        'ip_details': {}
    }
    
    # Parallel packet processing
    with ThreadPoolExecutor(max_workers=4) as executor:
        packet_futures = {executor.submit(process_packet, packet): packet for packet in packets}
        for future in as_completed(packet_futures):
            if future.result():
                src, dst, proto = future.result()
                results['ip_sources'][src] += 1
                results['ip_destinations'][dst] += 1
                results['protocols'][proto] += 1

    # Convert Counters to dict
    results['ip_sources'] = dict(results['ip_sources'])
    results['ip_destinations'] = dict(results['ip_destinations'])
    results['protocols'] = dict(results['protocols'])
    
    # Analyze suspicious behavior without VirusTotal
    unique_ips = set(results['ip_sources'].keys()) | set(results['ip_destinations'].keys())
    suspicious_ips = analyze_suspicious_behavior(packets, unique_ips, results)
    results['suspicious_ips'] = suspicious_ips

    # Parallel connection analysis
    infection_data = analyze_suspicious_connections(packets)
    results['infection_analysis'] = infection_data

    # Add user behavior analysis
    user_data = parallel_user_analysis(packets)
    results['user_analysis'] = user_data

    if infection_data['potential_flag']:
        # Rechercher les informations supplémentaires dans les paquets
        user_data = extract_user_data(packets, infection_data['potential_flag'])
        
        # Créer le format JSON attendu pour l'API
        infection_data['flag_data'] = {
            "user_id": user_data.get('user_id', 'unknown'),
            "lines": [
                user_data.get('mac_address', ''),
                infection_data['potential_flag'],  # IP address
                user_data.get('hostname', ''),
                user_data.get('username', '')
            ]
        }
    return results

def process_packet(packet):
    if IP in packet:
        return packet[IP].src, packet[IP].dst, packet[IP].proto
    return None

def analyze_suspicious_behavior(packets, unique_ips, results):
    suspicious_ips = []
    ip_details = {}

    for ip in unique_ips:
        # Calculer les statistiques de base
        details = {
            'total_packets_sent': results['ip_sources'].get(ip, 0),
            'total_packets_received': results['ip_destinations'].get(ip, 0),
            'ports_used': set(),
            'connection_count': 0,
            'data_volume': 0,
            'suspicious_indicators': []
        }

        # Analyser les paquets pour cette IP
        for packet in packets:
            if IP in packet:
                if packet[IP].src == ip or packet[IP].dst == ip:
                    details['connection_count'] += 1
                    if hasattr(packet, 'sport'):
                        details['ports_used'].add(packet.sport)
                    if hasattr(packet, 'dport'):
                        details['ports_used'].add(packet.dport)
                    if hasattr(packet, 'len'):
                        details['data_volume'] += packet.len

        # Évaluer les indicateurs de comportement suspect
        if details['connection_count'] > 100:
            details['suspicious_indicators'].append('Nombre élevé de connexions')
        if len(details['ports_used']) > 20:
            details['suspicious_indicators'].append('Utilisation de nombreux ports différents')
        if details['data_volume'] > 1000000:  # Plus de 1MB
            details['suspicious_indicators'].append('Volume de données important')

        # Convertir ports_used en liste pour la sérialisation JSON
        details['ports_used'] = list(details['ports_used'])

        # Ajouter aux IPs suspectes si des indicateurs sont présents
        if details['suspicious_indicators']:
            suspicious_ips.append({
                'ip': ip,
                'indicators': details['suspicious_indicators'],
                'risk_level': 'À vérifier',
                'verified': False
            })

        ip_details[ip] = details

    results['ip_details'] = ip_details
    return suspicious_ips

def parallel_user_analysis(packets):
    time.sleep(0.1)  # Reduced sleep time
    return analyze_user_behavior(packets)

def analyze_suspicious_connections(packets):
    infection_data = {
        'infected_machines': [],
        'malicious_sources': [],
        'suspicious_patterns': [],
        'potential_flag': None,
        'infection_details': {},
        'flag_data': None  # Nouveau champ pour le format JSON attendu
    }

    # Analyse des connexions
    connection_pairs = {}
    first_seen = {}
    last_seen = {}
    geo_data = {}

    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            timestamp = packet.time
            
            # Enregistrer les timestamps pour chaque IP
            for ip in [src, dst]:
                if ip not in first_seen:
                    first_seen[ip] = timestamp
                last_seen[ip] = timestamp

            # Stocker les paires de connexions
            key = f"{src}->{dst}"
            if key not in connection_pairs:
                connection_pairs[key] = {
                    'count': 0,
                    'source': src,
                    'destination': dst,
                    'timestamps': [],
                    'intervals': [],
                    'data_size': []
                }
            
            connection_pairs[key]['count'] += 1
            connection_pairs[key]['timestamps'].append(packet.time)
            if hasattr(packet, 'len'):
                connection_pairs[key]['data_size'].append(packet.len)

    # Pour chaque machine infectée, collecter les détails
    for ip in infection_data['infected_machines']:
        infection_data['infection_details'][ip] = {
            'first_seen': first_seen.get(ip),
            'last_seen': last_seen.get(ip),
            'infection_duration': last_seen.get(ip) - first_seen.get(ip) if first_seen.get(ip) else 0,
            'attacker': next((s for s in infection_data['malicious_sources'] 
                            if any(p['source'] == s and p['destination'] == ip 
                                for p in infection_data['suspicious_patterns'])), 'Unknown'),
            'country': get_ip_country(ip),
            'total_connections': sum(1 for p in infection_data['suspicious_patterns'] 
                                   if p['destination'] == ip),
            'attack_pattern': analyze_attack_pattern(ip, infection_data['suspicious_patterns'])
        }

    # Analyse approfondie pour trouver le flag
    potential_flags = {}
    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            if src not in potential_flags:
                potential_flags[src] = {
                    'packet_count': 0,
                    'unique_dst': set(),
                    'timestamps': [],
                    'data_size': 0,
                    'port_patterns': Counter()
                }
            
            potential_flags[src]['packet_count'] += 1
            potential_flags[src]['unique_dst'].add(packet[IP].dst)
            potential_flags[src]['timestamps'].append(packet.time)
            if hasattr(packet, 'len'):
                potential_flags[src]['data_size'] += packet.len
            if hasattr(packet, 'dport'):
                potential_flags[src]['port_patterns'][packet.dport] += 1

    # Identifier le flag en utilisant des critères spécifiques
    for ip, data in potential_flags.items():
        score = 0
        reasons = []

        # Critère 1: Beaucoup de connexions vers peu de destinations
        if len(data['unique_dst']) < 3 and data['packet_count'] > 50:
            score += 3
            reasons.append("Connexions répétitives vers destinations limitées")

        # Critère 2: Modèle de ports suspects (ex: ports communs de malware)
        suspicious_ports = [445, 135, 3389, 22, 4444, 8080]
        if any(port in data['port_patterns'] for port in suspicious_ports):
            score += 2
            reasons.append("Utilisation de ports suspects")

        # Critère 3: Intervalle régulier entre les paquets (bot-like)
        if len(data['timestamps']) > 2:
            intervals = [data['timestamps'][i+1] - data['timestamps'][i] 
                        for i in range(len(data['timestamps'])-1)]
            avg_interval = sum(intervals) / len(intervals)
            if 0.1 < avg_interval < 1.0:  # Intervalle suspect
                score += 2
                reasons.append("Intervalle régulier entre les paquets")

        # Si le score est suffisamment élevé, c'est probablement notre flag
        if score >= 5:
            infection_data['potential_flag'] = ip
            infection_data['flag_evidence'] = {
                'score': score,
                'reasons': reasons,
                'data_transferred': data['data_size'],
                'connection_count': data['packet_count'],
                'unique_destinations': len(data['unique_dst']),
                'timestamp_first': min(data['timestamps']),
                'timestamp_last': max(data['timestamps']),
                'duration': max(data['timestamps']) - min(data['timestamps'])
            }

    # Si on trouve un flag, on ajoute les données au format attendu
    if infection_data['potential_flag']:
        # Rechercher les informations supplémentaires dans les paquets
        user_data = extract_user_data(packets, infection_data['potential_flag'])
        
        # Créer le format JSON attendu
        infection_data['flag_data'] = {
            "user_id": user_data.get('user_id', 'unknown'),
            "lines": [
                user_data.get('mac_address', ''),
                infection_data['potential_flag'],  # IP address
                user_data.get('hostname', ''),
                user_data.get('username', '')
            ],
            "flag": f"HACK{{{generate_flag_hash(infection_data['potential_flag'])}}}"
        }

    return infection_data

def extract_user_data(packets, target_ip):
    """Extrait les informations supplémentaires des paquets pour une IP donnée"""
    from scapy.layers.l2 import Ether
    from scapy.layers.netbios import NBTDatagram
    from scapy.layers.smb2 import SMB2_Header  # Utilisation de SMB2 au lieu de SMB1
    
    user_data = {
        'mac_address': '',
        'hostname': '',
        'username': '',
        'user_id': ''
    }
    
    for packet in packets:
        if IP in packet and packet[IP].src == target_ip:
            # Extraire l'adresse MAC
            if Ether in packet:
                user_data['mac_address'] = packet[Ether].src
            
            # Tenter d'extraire le hostname et username
            if NBTDatagram in packet:
                try:
                    user_data['hostname'] = packet[NBTDatagram].NETBIOS_NAME.decode('utf-8').strip()
                except:
                    pass
            
            # Utiliser SMB2 pour les informations d'authentification
            if SMB2_Header in packet:
                try:
                    # Extraire le nom d'utilisateur des paquets SMB2
                    if hasattr(packet[SMB2_Header], 'SessionSetup'):
                        session_data = packet[SMB2_Header].SessionSetup
                        if hasattr(session_data, 'Account'):
                            user_data['username'] = session_data.Account
                except Exception as e:
                    logger.debug(f"Erreur lors de l'extraction SMB2: {str(e)}")
                    pass
    
    # Générer un user_id si non trouvé
    if not user_data['user_id']:
        user_data['user_id'] = f"user_{target_ip.replace('.', '_')}"
                
    return user_data


def generate_flag_hash(ip):
    """Génère un hash unique pour le flag basé sur l'IP"""
    import hashlib
    return hashlib.md5(ip.encode()).hexdigest()[:12]

def get_ip_country(ip):
    try:
        from geoip2 import database
        reader = database.Reader('GeoLite2-Country.mmdb')
        response = reader.country(ip)
        return response.country.name
    except:
        return "Pays inconnu"

def analyze_attack_pattern(ip, patterns):
    relevant_patterns = [p for p in patterns if p['destination'] == ip]
    if not relevant_patterns:
        return "Inconnu"
    
    # Analyser le type d'attaque basé sur les modèles
    if any(p['count'] > 100 for p in relevant_patterns):
        return "Attaque par force brute"
    elif any(p.get('data_transferred', 0) > 10000 for p in relevant_patterns):
        return "Exfiltration de données"
    else:
        return "Connexions suspectes"

def analyze_user_behavior(packets):
    user_data = {
        'legitimate_users': [],
        'suspicious_users': [],
        'behavior_patterns': []
    }
    
    # Analyse par IP
    ip_behavior = {}
    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            if src not in ip_behavior:
                ip_behavior[src] = {
                    'ip': src,
                    'packet_count': 0,
                    'destinations': set(),
                    'protocols': set(),
                    'timestamps': [],
                    'avg_interval': 0
                }
            
            ip_behavior[src]['packet_count'] += 1
            ip_behavior[src]['destinations'].add(packet[IP].dst)
            ip_behavior[src]['protocols'].add(packet[IP].proto)
            ip_behavior[src]['timestamps'].append(packet.time)

    # Analyser chaque IP pour déterminer si c'est un vrai utilisateur
    for ip, data in ip_behavior.items():
        # Calculer l'intervalle moyen entre les paquets
        if len(data['timestamps']) > 1:
            intervals = [data['timestamps'][i+1] - data['timestamps'][i] 
                       for i in range(len(data['timestamps'])-1)]
            data['avg_interval'] = sum(intervals) / len(intervals)

        # Critères de détection des vrais utilisateurs
        is_legitimate = True
        reasons = []

        # 1. Trop de paquets en peu de temps
        if data['packet_count'] > 1000 and data['avg_interval'] < 0.1:
            is_legitimate = False
            reasons.append('Trafic anormalement élevé')

        # 2. Trop de destinations différentes
        if len(data['destinations']) > 100:
            is_legitimate = False
            reasons.append('Nombre suspect de destinations')

        # 3. Comportement trop régulier (bot)
        if data['avg_interval'] > 0 and data['avg_interval'] < 0.01:
            is_legitimate = False
            reasons.append('Modèle de trafic automatisé')

        behavior_data = {
            'ip': ip,
            'packet_count': data['packet_count'],
            'unique_destinations': len(data['destinations']),
            'protocols_used': len(data['protocols']),
            'avg_interval': data['avg_interval'],
            'reasons': reasons
        }

        if is_legitimate:
            user_data['legitimate_users'].append(behavior_data)
        else:
            user_data['suspicious_users'].append(behavior_data)
            user_data['behavior_patterns'].append({
                'ip': ip,
                'type': 'suspicious_behavior',
                'reasons': reasons
            })

    return user_data
