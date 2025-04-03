from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
import os
import logging
from analyze import analyze_pcap
from virustotal import check_ip_reputation
import requests
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set API key directly in code
os.environ['VIRUSTOTAL_API_KEY'] = '6c54c23d7150b1258739b81457dd4e9a74119516b2c5444e711f8b9f89e0fd58'

app = Flask(__name__)
app.config.update(
    UPLOAD_FOLDER='uploads',
    ENV='development',
    DEBUG=True
)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

API_URL = "http://93.127.203.48:5000/pcap/latest"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze_local', methods=['POST'])
def analyze_local():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
    if file:
        try:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Analyse locale uniquement
            results = analyze_pcap(filepath)
            
            return jsonify({
                'success': True,
                'local_results': results
            })
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse locale: {str(e)}")
            return jsonify({
                'success': False,
                'error': f"Erreur lors de l'analyse: {str(e)}"
            }), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
    if file:
        try:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Configuration de la session avec retry et timeouts optimisés
            session = requests.Session()
            retries = requests.adapters.Retry(
                total=2,  # Réduire le nombre de tentatives
                backoff_factor=0.5,  # Réduire le délai entre les tentatives
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=['POST'],
                raise_on_status=True
            )
            session.mount('http://', requests.adapters.HTTPAdapter(max_retries=retries))

            try:
                # Analyse locale du fichier
                results = analyze_pcap(filepath)
                
                # Stocker les résultats pour la vérification des IP
                if not hasattr(upload_file, 'results_cache'):
                    upload_file.results_cache = {}
                upload_file.results_cache[filename] = results
                check_ip.last_analysis_results = results
                
                # Tentative de soumission au serveur distant avec timeout réduit
                submit_url = "http://93.127.203.48:5000/pcap/submit"
                with open(filepath, 'rb') as pcap_file:
                    files = {'file': (filename, pcap_file, 'application/vnd.tcpdump.pcap')}
                    response = session.post(submit_url, files=files, timeout=10)
                    response.raise_for_status()
                
                return jsonify({
                    'success': True,
                    'local_results': results,
                    'remote_submission': 'success'
                })
                
            except requests.exceptions.Timeout:
                logger.warning("Timeout lors de la soumission au serveur distant - utilisation des résultats locaux")
                return jsonify({
                    'success': True,
                    'local_results': results,
                    'remote_submission': 'timeout',
                    'message': 'Analyse effectuée localement uniquement en raison d\'un timeout serveur',
                    'cached': True
                })
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Erreur lors de la soumission au serveur: {str(e)}")
                return jsonify({
                    'success': True,
                    'local_results': results,
                    'remote_submission': 'error',
                    'message': 'Analyse effectuée localement uniquement en raison d\'une erreur de connexion',
                    'cached': True
                })
                
        except Exception as e:
            logger.error(f"Erreur lors du traitement du fichier: {str(e)}")
            return jsonify({
                'success': False,
                'error': f"Erreur lors du traitement: {str(e)}"
            }), 500

@app.route('/check_ip', methods=['POST'])
def check_ip():
    ip = request.json.get('ip')
    verify = request.json.get('verify', False)
    
    if not ip:
        return jsonify({'error': 'No IP provided'})
        
    # Récupérer les détails de l'IP depuis les résultats d'analyse
    if hasattr(check_ip, 'last_analysis_results') and ip in check_ip.last_analysis_results['ip_details']:
        ip_details = check_ip.last_analysis_results['ip_details'][ip]
    else:
        return jsonify({'error': 'IP non trouvée dans l\'analyse'})
    
    # Si la vérification VirusTotal est demandée
    if verify:
        # Vérifier l'IP avec VirusTotal
        vt_result = check_ip_reputation(ip,'6c54c23d7150b1258739b81457dd4e9a74119516b2c5444e711f8b9f89e0fd58')
        # Mettre à jour les détails de l'IP avec le résultat VirusTotal
        if vt_result:
            ip_details['virustotal'] = vt_result
        else:
            ip_details['virustotal'] = {'error': 'VirusTotal API error'}
        ip_details['virustotal'] = vt_result
        
    return jsonify({
        'ip': ip,
        'details': ip_details,
        'verified': verify
    })
    
@app.route('/fetch_pcap', methods=['GET'])
def fetch_pcap():
    # Utiliser directement le fichier local par défaut
    local_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'ex4.pcap')
    
    if os.path.exists(local_filepath):
        try:
            # Analyser le fichier local
            results = analyze_pcap(local_filepath)
            
            # Tenter la connexion au serveur en arrière-plan
            try:
                session = requests.Session()
                retries = requests.adapters.Retry(
                    total=2,
                    backoff_factor=0.5,
                    status_forcelist=[500, 502, 503, 504]
                )
                session.mount('http://', requests.adapters.HTTPAdapter(max_retries=retries))
                response = session.get(API_URL, timeout=5)
                
                if response.status_code == 200:
                    # Sauvegarder le nouveau fichier
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    new_filename = f"pcap_{timestamp}.pcap"
                    new_filepath = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                    
                    with open(new_filepath, 'wb') as f:
                        f.write(response.content)
                    
                    # Analyser le nouveau fichier
                    new_results = analyze_pcap(new_filepath)
                    
                    return jsonify({
                        'success': True,
                        'filename': new_filename,
                        'results': new_results
                    })
                    
            except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
                logger.warning(f"Utilisation des données locales (erreur serveur: {str(e)})")
                
            # Retourner les résultats locaux si la connexion échoue
            return jsonify({
                'success': True,
                'filename': 'ex4.pcap',
                'results': results,
                'source': 'local'
            })
                
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du fichier local: {str(e)}")
            return jsonify({
                'success': False,
                'error': f"Erreur d'analyse: {str(e)}"
            })
    else:
        return jsonify({
            'success': False,
            'error': "Fichier local non disponible"
        })

@app.route('/get_filename', methods=['GET'])
def get_filename():
    try:
        response = requests.get("http://93.127.203.48:5000/pcap/latest/filename")
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({
                'success': False,
                'error': f"API error: {response.status_code}"
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/submit_results', methods=['POST'])
def submit_results():
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'})
            
        try:
            response = requests.post(
                "http://93.127.203.48:5000/pcap/submit",
                json=data,
                timeout=15
            )
            response.raise_for_status()
        except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
            logging.error(f"Erreur de soumission: {str(e)}")
            return jsonify({"success": False, "error": str(e)})
        
        if response.status_code == 200:
            return jsonify({
                'success': True,
                'flag': response.json().get('flag')
            })
        else:
            return jsonify({
                'success': False,
                'error': f"API error: {response.status_code}",
                'message': response.text
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


if __name__ == '__main__':
    logger.info('Starting Security Analysis Dashboard...')
    logger.info('Server running on http://localhost:5000')
    app.run(host='0.0.0.0', port=5000)
