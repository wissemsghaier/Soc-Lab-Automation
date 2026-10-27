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
  - Detection des signatures Suricata WAN LAB 1000201 a 1000205.
  - La regle de base filtre le champ decode `suricata_sid`, sans imposer
    un decodeur custom nomme `pfsense-suricata-wanlab`.
  - Le decodeur actif doit extraire `suricata_sid`; les logs JSON EVE utilisant
    `alert.signature_id` ne correspondent pas directement a ces regles.
  - Avant redemarrage, valider avec
    `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t`.
    Utiliser ensuite `wazuh-logtest` avec un vrai log pour verifier le decodage
    et la regle declenchee.

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
