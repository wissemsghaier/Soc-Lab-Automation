# Dossier config/wazuh/rules/linux

Ce dossier contient les regles Linux custom de PHASE4.

## Fichiers et role

- 001-linux-ufw.xml
  - Detection UFW TCP/ICMP.
  - Correlation scan de ports et flood ICMP.

- 003-linux-auditd.xml
  - Detection basee sur auditd (auth echec, exec, identity, config change).

- 004-linux-auth.xml
  - Detection SSH failed/success.
  - Correlation brute-force SSH.
  - Activite sudo et su.

- 005-linux-syslog.xml
  - Detection incidents systeme (services failed, OOM killer).

- 006-linux-cron.xml
  - Detection activite cron root, repetition anormale et echec execution.

- [010-linux-pfsense_suricata_wanlab_rules.xml](./010-linux-pfsense_suricata_wanlab_rules.xml)
  - Classification des alertes Syslog Suricata IPv4 :
    - 110201 : SID 1000201 ou 1000206 (ICMP).
    - 110202 : SID 1000202 ou 2003068 (scan SSH, dont ET SCAN observe dans le lab).
    - 110203 : SID 1000203 (RDP).
    - 110204 : SID 1000204 (SMB).
    - 110205 : SID 1000205 (HTTP/HTTPS).
  - La regle 110200 exige le decodeur `pfsense-suricata-wanlab` et reste
    l alerte generale pour les SID sans classification specialisee.
  - Le decodeur fourni accepte les messages WAN LAB et ET SCAN au format
    texte avec priorite et protocole, ainsi que l ICMP sans ports.
  - Le decodeur actif doit extraire `suricata_sid`; les logs JSON EVE utilisant
    `alert.signature_id` ne correspondent pas directement a ces regles.
  - Avant redemarrage, valider avec
    `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t`.
    Utiliser ensuite `wazuh-logtest` avec un vrai log pour verifier le decodage
    et la regle declenchee.
  - Le script apply Phase 4 ne deploie pas les decodeurs. Copier le decodeur
    separement dans `/var/ossec/etc/decoders/`, sans conserver une autre
    definition active du meme nom. Dans le lab, `pfsense_suricata_wanlab.xml`
    existe deja : le sauvegarder hors du repertoire des decodeurs avant
    de le remplacer par le decodeur fourni.
  - Les signatures personnalisees doivent etre chargees sur l instance Suricata
    qui voit le trafic, avec un HOME_NET adapte et l export Syslog des alertes
    active. Aucun mapping ET supplementaire n est suppose pour RDP, SMB ou HTTP.
  - Regression locale : `python scripts/test_suricata_wanlab_rules.py`.
    Ce test controle les expressions et les mappings, pas le moteur Wazuh.

## Utilite SOC

- Couvre les vecteurs Linux frequents d un lab:
  - reconnaissance reseau,
  - brute-force,
  - deni de service,
  - persistence et usage privilegies,
  - incidents disponibilite.

## Etapes et commandes

1. Appliquer la configuration PHASE4:

```bash
sudo PROJECT_DIR="$(pwd)" MANAGER_CONTAINER=single-node-wazuh.manager-1 bash scripts/apply_phase4_wazuh_docker.sh
```

2. Lancer simulation Linux:

```bash
bash scripts/run_phase4_linux_attack_test.sh --target-ip 10.10.0.22
```

3. Valider les rule.id Linux detectes:

```bash
python3 scripts/validate_phase4_rule_ids.py --mode linux --container single-node-wazuh.manager-1
```
