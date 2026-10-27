# Next-Gen AI-Driven SOC

Ce projet implemente un lab SOC oriente detection, triage et orchestration.

![Home Lab SOC Architecture](docs/assets/home-lab-soc-architecture.png)

Cette image represente la chaine complete de detection, investigation, enrichment et reponse.

Objectif global:
- Detecter des attaques Linux et Windows avec Wazuh.
- Creer automatiquement des alertes TheHive.
- Enrichir les observables via Cortex et MISP.
- Piloter les actions analyste via Shuffle.

## Architecture detaillee

### 1) Zone attaque et generation des evenements

- Kali Linux joue le role machine d attaque/test.
- Active Directory (Windows Server) et les endpoints recoivent les actions de test.
- Les evenements de securite et reseau sont generes cote Windows et Linux.

Utilite:
- Simuler des scenarios reels (scan, brute force, activite suspecte) dans un lab controle.

### 2) Detection et correlation (Wazuh)

- Wazuh collecte les logs Linux et Windows.
- Les regles custom PHASE4 detectent:
	- scan TCP,
	- flood ICMP,
	- brute force,
	- comportements Sysmon (PowerShell encode, LOLBins, possible C2, etc.).
- Wazuh genere une alerte avec contexte technique (rule id, severite, host, champs event).

Utilite:
- Transformer un grand volume de logs bruts en alertes qualifiees et actionnables.

### 3) Gestion d incident (TheHive)

- Une integration Python (automation/wazuh_to_thehive.py) pousse l alerte vers TheHive.
- L alerte inclut:
	- titre standardise,
	- description detaillee,
	- severite mappee,
	- tags,
	- observables extraits automatiquement.
- sourceRef stable evite les doublons logiques sur une meme attaque repetee.

Utilite:
- Centraliser la gestion d incident et preparer le travail analyste sans duplication inutile.

### 4) Enrichment (Cortex, AbuseIPDB, MISP, VirusTotal)

- TheHive/Shuffle envoie les observables vers Cortex.
- Cortex execute les analyzers (AbuseIPDB, VirusTotal, MISP, autres).
- MISP apporte le contexte de threat intelligence interne/externe.

Utilite:
- Donner une priorisation basee sur des preuves (reputation IP, malveillance hash/url, correspondances TI).

### 5) Orchestration SOAR (Shuffle)

- Shuffle declenche les playbooks a la reception d alertes/cases.
- Le workflow consolide les resultats d enrichissement.
- Il cree les taches de decision et trace les etapes (audit trail).

Utilite:
- Standardiser les traitements et reduire le temps de reponse.

### 6) Notification et decision humaine (Telegram + analyste)

- Telegram envoie les notifications operationnelles.
- L analyste valide la decision finale:
	- bloquer IP,
	- isoler poste,
	- supprimer fichier,
	- desactiver compte,
	- publier IoC dans MISP.

Utilite:
- Garder l humain dans la boucle pour les actions a impact.

### 7) Reponse et boucle d amelioration

- Actions de reponse: containment, eradication, recovery.
- Lessons learned reinjectees dans:
	- regles Wazuh,
	- playbooks Shuffle,
	- politiques de priorisation.

Utilite:
- Amelioration continue de la qualite detection et de la vitesse de traitement.

## Flux operationnel resumee

1. Kali lance une simulation d attaque.
2. Les systemes cibles produisent logs et evenements.
3. Wazuh detecte et cree une alerte.
4. TheHive recoit et structure l incident.
5. Cortex/AbuseIPDB/MISP/VirusTotal enrichissent les observables.
6. Shuffle consolide et prepare la decision.
7. Telegram notifie l equipe SOC.
8. L analyste approuve ou rejette l action.
9. Les actions autorisees sont executees.
10. Le resultat est trace pour audit et amelioration.

Architecture fonctionnelle:
1. Wazuh collecte et corrige les evenements.
2. Regles custom PHASE4 detectent scans, brute force, flood, comportements Sysmon.
3. Integration Python pousse les alertes vers TheHive avec sourceRef stable (anti-duplication).
4. Shuffle orchestre l enrichissement et la decision analyste.
5. Cortex lance les analyzers (AbuseIPDB, VirusTotal, MISP, etc.).

## Lecture rapide pour un nouveau membre

1. Lire d abord docs/README.md puis docs/PHASE4_WAZUH_DOCKER.md.
2. Lire config/README.md pour comprendre les stacks et regles.
3. Lire automation/README.md pour comprendre la logique Wazuh -> TheHive.
4. Lire scripts/README.md pour deploiement et tests.

## Arborescence principale

- automation/: code d integration et tests locaux d extraction d observables.
- config/: toutes les configurations Wazuh, Cortex, MISP, Shuffle et variables d environnement.
- docs/: runbooks, guides de test et mode operatoire.
- scripts/: scripts de deploiement et de validation.

## Resultat attendu du projet

Quand tout est en place:
- Une attaque detectee cote Linux/Windows remonte dans Wazuh.
- Une alerte est creee dans TheHive avec observables exploitables.
- Les enrichissements donnent du contexte de priorisation.
- L analyste valide les actions de containment avec tracabilite.

## Demarrage rapide (commandes)

1. Creer le fichier d environnement:

```bash
cp config/.env.example config/.env
```

PowerShell:

```powershell
Copy-Item config/.env.example config/.env
```

2. Demarrer les stacks conteneurisees:

```bash
docker compose -f config/cortex/docker-compose.yml up -d
docker compose -f config/misp/docker-compose.yaml up -d
docker compose -f config/shuffle/docker-compose.yaml up -d
```

3. Appliquer PHASE4 sur le manager Wazuh Docker:

```bash
sudo PROJECT_DIR="$(pwd)" MANAGER_CONTAINER=single-node-wazuh.manager-1 bash scripts/apply_phase4_wazuh_docker.sh
```

4. Lancer les tests d attaque puis validation:

```bash
bash scripts/run_phase4_linux_attack_test.sh --target-ip 10.10.0.22
python3 scripts/validate_phase4_rule_ids.py --mode linux --container single-node-wazuh.manager-1
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_phase4_windows_attack_test.ps1 -TargetIp 10.10.0.33
python scripts/validate_phase4_rule_ids.py --mode windows --container single-node-wazuh.manager-1
```



1. Dashboard Command Center SOC
Objectif:

Avoir une vue globale en 30 secondes sur l’état sécurité.
Contenu détaillé:

KPI total alertes sur 24h.
KPI alertes critiques sur 24h.
Courbe alertes par heure sur 24h.
Camembert alertes par niveau de sévérité.
Top 10 agents qui génèrent le plus d’alertes.
Top 10 règles les plus déclenchées.
Tableau des 20 dernières alertes critiques avec timestamp, agent, rule id, description, source ip.
Utilité:

Prioriser rapidement les investigations.
Voir si le SOC est en surcharge.
Identifier immédiatement une machine bruyante ou compromise.
2. Dashboard Détection et Qualité des Règles
Objectif:

Mesurer ce que détectent les règles et améliorer leur qualité.
Contenu détaillé:

Top rule id sur 7 jours.
Top rule groups sur 7 jours.
Histogramme alertes par rule level.
Série temporelle des 10 rule id les plus fréquents.
Tableau règles les plus répétitives par même source ip.
Tableau règles critiques jamais vues récemment.
KPI ratio bruit:
alertes low severity / alertes totales.
Utilité:

Réduire les faux positifs.
Optimiser les règles custom.
Vérifier que les règles importantes déclenchent bien.
3. Dashboard Menaces Réseau
Objectif:

Détecter scans, brute force réseau, C2 possible, flux anormaux.
Contenu détaillé:

Courbe événements réseau par heure.
Top source ip externes.
Top destination ip internes.
Top ports ciblés.
Répartition protocoles tcp, udp, icmp.
Tableau alertes de scan et flood.
Tableau événements firewall bloqués vs autorisés.
Carte géographique des ip sources si la géolocalisation est activée.
Utilité:

Identifier rapidement l’attaquant principal.
Voir si l’attaque est large ou ciblée.
Donner des éléments concrets pour blocage ip ou segmentation.
4. Dashboard Identité et Authentification
Objectif:

Surveiller les attaques sur comptes et accès.
Contenu détaillé:

KPI échecs login sur 24h.
KPI succès login sur 24h.
Courbe failed logon par heure.
Top comptes avec le plus d’échecs.
Top ip sources d’échecs d’authentification.
Tableau détections brute force (Windows et Linux).
Heatmap logins par heure et par jour.
Tableau succès après plusieurs échecs (pattern suspect).
Utilité:

Détecter bruteforce, password spraying, tentative de prise de compte.
Prioriser verrouillage compte, reset mot de passe, blocage ip.
Détecter une compromission en phase initiale.
5. Dashboard Endpoints et Santé des Agents
Objectif:

Garantir la visibilité SOC et voir les signaux compromission endpoint.
Contenu détaillé:

KPI agents connectés vs déconnectés.
Liste agents inactifs depuis plus de X minutes.
Courbe changements fichiers critiques (FIM) par hôte.
Courbe alertes Sysmon process suspectes.
Top commandes/processus à risque (PowerShell encodé, LOLBins, etc.).
Tableau incidents système Linux (service failed, OOM, erreurs critiques).
Tableau résumé par host:
niveau max, nombre alertes, dernière alerte.
Utilité:

S’assurer que les agents remontent bien.
Détecter activité malveillante endpoint tôt.
Distinguer panne technique vs incident sécurité.
Plan pratique pour construire ces 5 dashboards en Semaine 2:

Jour 1: Command Center SOC.
Jour 2: Détection et Qualité des Règles.
Jour 3: Menaces Réseau.
Jour 4: Identité et Authentification.
Jour 5: Endpoints et Santé des Agents + ajustements.
Si tu veux, je peux te donner ensuite la version opérationnelle:

Les visualisations exactes à créer dans Wazuh une par une.
Les filtres recommandés pour chaque widget.
Une checklist validation pour savoir si chaque dashboard est prêt production.





Vérification	Ce qu’on attend	Ton test
1. Éviter les doublons	Envoyer exactement la même alerte deux fois : TheHive ne doit la créer qu’une fois.	Testé : le deuxième envoi a été refusé avec already exists.
2. Conserver les nouvelles preuves	Envoyer un événement Sysmon différent, mais lié à la même attaque : sa nouvelle information doit être conservée.	Pas encore testé.
3. Continuer si Cortex ne répond pas	Même si l’enrichissement dépasse son délai, l’alerte doit rester accessible dans TheHive pour l’analyste.	Pas encore testé.






6. Dashboard Linux — Intégrité et Accès aux Fichiers
Objectif :

Surveiller les changements sur les fichiers et dossiers sensibles Linux, identifier les opérations inhabituelles et faciliter leur investigation.

Contenu détaillé :

KPI alertes de changements : ajouts, modifications et suppressions.
KPI hôtes et chemins distincts concernés.
Courbe des changements FIM par heure et par hôte.
Top fichiers et dossiers avec le plus de changements.
Tableau des changements sur les fichiers critiques : comptes locaux, sudoers, configuration SSH, services et tâches planifiées.
Tableau des changements de permissions et de propriétaires, selon les attributs collectés.
Tableau détaillé : date, hôte, chemin, type de changement, attributs modifiés et niveau d’alerte.
Tableau des opérations auditées sur les fichiers : utilisateur, processus, opération et résultat, si la collecte auditd est configurée.
Chronologie des événements pour un fichier ou un dossier sélectionné.
Tableau résumé par hôte : nombre d’alertes, niveau maximal et dernier changement détecté.
Utilité :

Repérer les modifications sensibles ou inattendues.
Identifier une altération de configuration, un changement de privilèges ou une persistance potentielle.
Attribuer les opérations à un utilisateur et un processus lorsque ces informations sont disponibles.
Distinguer une maintenance légitime d’une activité suspecte.
7. Dashboard Windows — Intégrité et Accès aux Fichiers
Objectif :

Surveiller l’intégrité des fichiers et dossiers sensibles Windows, examiner les changements de permissions et investiguer les opérations d’accès auditées.

Contenu détaillé :

KPI alertes de changements : ajouts, modifications et suppressions.
KPI hôtes et chemins distincts concernés.
Courbe des changements FIM par heure et par hôte.
Top fichiers et dossiers avec le plus de changements.
Tableau des changements sur les fichiers critiques : fichier hosts, dossier Startup, exécutables système et configurations applicatives sélectionnés.
Tableau des changements de permissions et de propriétaires, selon les attributs collectés.
Tableau détaillé : date, hôte, chemin, type de changement, attributs modifiés et niveau d’alerte.
Tableau des opérations auditées sur les fichiers : compte, processus, objet, droits utilisés et résultat, selon les événements collectés.
Tableau des tentatives d’accès refusées, si l’audit des échecs est configuré.
Chronologie des événements pour un fichier ou un dossier sélectionné.
Tableau résumé par hôte : nombre d’alertes, niveau maximal et dernier changement détecté.
Utilité :

Repérer l’altération de fichiers système ou applicatifs.
Surveiller les emplacements pouvant servir à la persistance.
Identifier des changements de permissions ou des opérations d’accès inhabituelles.
Faciliter l’investigation et la priorisation des incidents.






syscheck.mode = whodata
syscheck.audit.user.name
syscheck.audit.process.name
syscheck.audit.process.id