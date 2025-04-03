function analyzeLocal() {
    const fileInput = document.getElementById('pcapFile');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Veuillez sélectionner un fichier d\'abord');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    fetch('/analyze_local', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => displayResults(data))
    .catch(error => {
        console.error('Erreur:', error);
        alert('Erreur lors de l\'analyse locale: ' + error);
    });
}

function uploadFile() {
    const fileInput = document.getElementById('pcapFile');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Veuillez sélectionner un fichier d\'abord');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => displayResults(data))
    .catch(error => console.error('Erreur:', error));
}

function displayFinalResults(results) {
    const threatResults = document.getElementById('threatResults');
    if (results.length === 0) {
        threatResults.innerHTML = '<p class="error">Aucun résultat trouvé depuis VirusTotal</p>';
        return;
    }

    const summary = document.createElement('div');
    summary.className = 'analysis-summary';
    summary.innerHTML = `
        <h3>Analyse Terminée</h3>
        <p>Total des IPs analysées: ${results.length}</p>
        <p>IPs à Risque Élevé: ${results.filter(r => r.threat_level === 'High').length}</p>
        <p>IPs à Risque Moyen: ${results.filter(r => r.threat_level === 'Medium').length}</p>
        <p>IPs à Faible Risque: ${results.filter(r => r.threat_level === 'Low').length}</p>
    `;
    
    threatResults.prepend(summary);
}

function fetchPcapFromAPI() {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    fetch('/fetch_pcap', { 
        signal: controller.signal 
    })
    .then(response => {
        clearTimeout(timeoutId);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    })
    .then(data => {
        if (data.success) {
            displayResults(data.results);
            alert('Fichier PCAP récupéré et analysé avec succès: ' + data.filename);
        } else {
            alert('Erreur serveur: ' + data.error);
        }
    })
    .catch(error => {
        clearTimeout(timeoutId);
        console.error('Erreur:', error);
        const errorMsg = error.name === 'AbortError' 
            ? 'Timeout : Le serveur n\'a pas répondu dans les 10 secondes' 
            : `Erreur réseau : ${error.message}`;
        alert(`Échec de la récupération - ${errorMsg}`);
    });
}

function getActiveFilename() {
    fetch('/get_filename')
        .then(response => response.json())
        .then(data => {
            if (data.filename) {
                alert('Fichier actif: ' + data.filename);
            } else {
                alert('Erreur lors de la récupération du nom de fichier');
            }
        })
        .catch(error => {
            console.error('Erreur:', error);
            alert('Erreur lors de la récupération du nom de fichier');
        });
}

function submitResults(flagData) {
    if (!flagData) {
        alert('Aucune donnée de flag à soumettre');
        return;
    }
    
    fetch('/submit_results', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(flagData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Flag obtenu: ' + data.flag);
        } else {
            alert('Erreur lors de la soumission: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Erreur:', error);
        alert('Erreur lors de la soumission des résultats');
    });
}



function displayResults(data) {
    if (!data || typeof data !== 'object') {
        console.error('Données invalides reçues:', data);
        const statistics = document.getElementById('statistics');
        statistics.innerHTML = '<div class="error-message">Erreur: Données invalides reçues du serveur</div>';
        return;
    }

    const statistics = document.getElementById('statistics');
    let analysisType = '';
    if (data.local_results) {
        analysisType = data.remote_submission ? 'Analyse Locale et Distante' : 'Analyse Locale';
        data = data.local_results;
    } else {
        analysisType = 'Analyse Standard';
    }

    statistics.innerHTML = `
        <div class="analysis-summary">
            <h3>${analysisType}</h3>
            <div class="analysis-badge ${data.remote_submission === 'timeout' ? 'warning' : 'success'}">
                ${data.remote_submission === 'timeout' ? '⚠️ Analyse locale uniquement (timeout serveur)' : 
                  data.remote_submission === 'error' ? '⚠️ Analyse locale uniquement (erreur serveur)' : 
                  '✅ Analyse complète'}
            </div>
            
            <!-- Section des Machines Suspectes et Infectées -->
            <div class="critical-findings">
                ${data.user_analysis && data.user_analysis.suspicious_users && data.user_analysis.suspicious_users.length ? `
                    <div class="suspicious-users-summary">
                        <h4>⚠️ Utilisateurs Suspects Détectés (${data.user_analysis.suspicious_users.length})</h4>
                        <ul class="suspicious-list">
                            ${data.user_analysis.suspicious_users.map(user => `
                                <li class="suspicious-item">
                                    <div class="ip-info">
                                        <strong>IP:</strong> ${user.ip || 'Inconnue'}
                                        <div class="reason">${(user.reasons || []).join(', ') || 'Raison inconnue'}</div>
                                    </div>
                                    <button onclick="quickCheckIp('${user.ip || ''}')"
                                            class="quick-check-btn">
                                        🔍 Vérifier
                                    </button>
                                </li>
                            `).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>

            <p><strong>Paquets Total:</strong> ${data.total_packets || 0}</p>
            <p><strong>Analysé le:</strong> ${new Date().toLocaleString('fr-FR')}</p>
        </div>
    `;

    // Afficher les résultats des menaces si disponibles
    const threatResults = document.getElementById('threatResults');
    if (data.threat_analysis) {
        let threatHtml = '<div class="threat-analysis">';
        
        const threatLevels = {
            high_risk: { title: 'IPs à Risque Élevé', class: 'high' },
            medium_risk: { title: 'IPs à Risque Moyen', class: 'medium' },
            low_risk: { title: 'IPs à Faible Risque', class: 'low' }
        };

        Object.entries(threatLevels).forEach(([level, info]) => {
            const threats = data.threat_analysis[level] || [];
            if (threats.length > 0) {
                threatHtml += `<h3 class="threat-level-${info.class}">${info.title}</h3>`;
                threats.forEach(threat => {
                    threatHtml += createThreatCard(threat);
                });
            }
        });
        
        threatHtml += '</div>';
        threatResults.innerHTML = threatHtml;
    }

    // Afficher le bouton de soumission si des données de flag sont présentes
    if (data.infection_analysis?.flag_data) {
        const submitButton = document.createElement('button');
        submitButton.className = 'btn';
        submitButton.textContent = 'Soumettre les résultats';
        submitButton.onclick = function() {
            submitResults(data.infection_analysis.flag_data);
        };
        
        const flagSection = document.querySelector('.flag-alert');
        if (flagSection) {
            flagSection.appendChild(submitButton);
        }
    }
}

function quickCheckIp(ip) {
    const threatResults = document.getElementById('threatResults');
    
    threatResults.innerHTML = `
        <div class="loading">
            <p>Analyse de l'IP ${ip} avec VirusTotal...</p>
        </div>
    `;

    fetch('/check_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(response => response.json())
    .then(data => {
        displayThreatLevel(data);
        threatResults.scrollIntoView({ behavior: 'smooth' });
    })
    .catch(error => {
        console.error('Erreur:', error);
        threatResults.innerHTML = '<p class="error">Erreur lors de l\'analyse</p>';
    });
}

function createInfectionSummary(infectionData) {
    if (!infectionData) return '';

    let flagHtml = '';
    if (infectionData.flag_data) {
        const flagData = infectionData.flag_data;
        flagHtml = `
            <div class="flag-alert">
                <h4>🚨 FLAG DÉTECTÉ 🚨</h4>
                <div class="flag-details">
                    <p><strong>User ID:</strong> ${flagData.user_id}</p>
                    <p><strong>Informations Machine:</strong></p>
                    <ul>
                        <li>MAC Address: ${flagData.lines[0]}</li>
                        <li>IP Address: ${flagData.lines[1]}</li>
                        <li>Hostname: ${flagData.lines[2]}</li>
                        <li>Username: ${flagData.lines[3]}</li>
                    </ul>
                    <p class="flag-code"><strong>Flag:</strong> ${flagData.flag}</p>
                </div>
            </div>
        `;
    }

    let attackSummary = '';
    if (infectionData.malicious_sources.length > 0 && infectionData.infected_machines.length > 0) {
        attackSummary = `
            <div class="attack-summary">
                <h3>Résumé de l'Attaque</h3>
                <div class="attack-flow">
                    <div class="attacker">
                        <h4>🚨 Machine Attaquante</h4>
                        <p>${infectionData.malicious_sources[0]}</p>
                    </div>
                    <div class="attack-arrow">➔</div>
                    <div class="victim">
                        <h4>⚠️ Machine Victime</h4>
                        <p>${infectionData.infected_machines[0]}</p>
                    </div>
                </div>
            </div>
        `;
    }

    return `
        <div class="infection-summary">
            ${attackSummary}
            ${flagHtml}
            <h4>Sources Malveillantes Détectées</h4>
            <ul class="malicious-sources">
                ${infectionData.malicious_sources.map(ip => `
                    <li class="threat-level-high">
                        <strong>IP Source:</strong> ${ip}
                    </li>
                `).join('')}
            </ul>

            <h4>Machines Potentiellement Infectées</h4>
            <ul class="infected-machines">
                ${infectionData.infected_machines.map(ip => `
                    <li class="threat-level-medium">
                        <strong>IP Machine:</strong> ${ip}
                    </li>
                `).join('')}
            </ul>

            <h4>Modèles de Connexions Suspectes</h4>
            <ul class="suspicious-patterns">
                ${infectionData.suspicious_patterns.map(pattern => `
                    <li>
                        <strong>Type:</strong> ${pattern.type}<br>
                        <strong>Source:</strong> ${pattern.source}<br>
                        <strong>Destination:</strong> ${pattern.destination}<br>
                        <strong>Nombre de connexions:</strong> ${pattern.count}
                    </li>
                `).join('')}
            </ul>
        </div>
    `;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function createThreatCard(threat) {
    const threatLevel = threat.threat_level?.toLowerCase() || 'unknown';
    return `
        <div class="threat-result ${threatLevel}-threat">
            <div class="threat-header">
                <h4>IP: ${threat.ip}</h4>
                <span class="threat-badge ${threatLevel}">
                    ${translateThreatLevel(threat.threat_level)}
                </span>
            </div>
            <div class="threat-details">
                <p><strong>Détections:</strong> ${threat.detections}</p>
                ${threat.details ? `
                    <ul>
                        <li>URLs Malveillantes: ${threat.details.detected_urls || 0}</li>
                        <li>Échantillons Malveillants: ${threat.details.detected_samples || 0}</li>
                        <li>Pays: ${threat.details.country || 'Inconnu'}</li>
                    </ul>
                ` : ''}
            </div>
            <div class="threat-indicator ${threatLevel}"></div>
        </div>
    `;
}

function translateThreatLevel(level) {
    const translations = {
        'High': 'Élevé',
        'Medium': 'Moyen',
        'Low': 'Faible',
        'Unknown': 'Inconnu'
    };
    return translations[level] || level;
}

function displayThreatLevel(data) {
    const threatResults = document.getElementById('threatResults');
    const threatLevel = data.threat_level?.toLowerCase() || 'unknown';
    
    const threatElement = document.createElement('div');
    threatElement.className = `threat-result ${threatLevel}`;
    threatElement.innerHTML = `
        <p><strong>IP:</strong> ${data.ip}</p>
        <p><strong>Niveau de Menace:</strong> 
            <span class="threat-level-text ${threatLevel}">
                ${translateThreatLevel(data.threat_level)}
            </span>
        </p>
        <p><strong>Total des Détections:</strong> ${data.detections}</p>
        ${data.details ? `
            <p><strong>Détails:</strong></p>
            <ul>
                <li>URLs Détectées: ${data.details.detected_urls || 0}</li>
                <li>Échantillons Détectés: ${data.details.detected_samples || 0}</li>
                <li>Pays: ${data.details.country || 'Inconnu'}</li>
                <li>Propriétaire AS: ${data.details.as_owner || 'Inconnu'}</li>
            </ul>
        ` : ''}
        <div class="threat-bar ${threatLevel}"></div>
        <hr>
    `;
    
    threatResults.appendChild(threatElement);
}
