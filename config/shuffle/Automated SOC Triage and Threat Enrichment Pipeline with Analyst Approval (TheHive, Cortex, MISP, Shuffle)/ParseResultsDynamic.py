import json
import ast

# Sortie complète du nœud GetJobResult.
# IMPORTANT : conserver le $ devant getjobresult.
raw = r'''$getjobresult'''


def decode(value):
    """Convertir du JSON ou une représentation Python en objet."""
    if not isinstance(value, str):
        return value

    text = value.strip()

    if not text:
        raise ValueError("Donnée vide")

    try:
        return json.loads(text, strict=False)
    except (ValueError, TypeError):
        return ast.literal_eval(text)


def number(value):
    """Lire un entier positif ou nul, sans convertir une absence en zéro."""
    if value is None or isinstance(value, bool):
        return None

    try:
        parsed = float(value)

        if parsed < 0 or not parsed.is_integer():
            return None

        return int(parsed)
    except (ValueError, TypeError, OverflowError):
        return None


def maximum(current, new):
    """Conserver la plus grande valeur disponible."""
    if new is None:
        return current

    if current is None:
        return new

    return max(current, new)


def display(value):
    return "N/A" if value is None else str(value)


def summarize():
    # 1. Charger les réponses de GetJobResult.
    try:
        jobs = decode(raw)
    except Exception:
        return (
            "⚠️ Résultats illisibles.\n"
            "Vérifier la référence au nœud GetJobResult dans BuildSummary.\n"
            "Niveau indicatif : INDETERMINE."
        )

    if isinstance(jobs, dict):
        jobs = [jobs]

    if not isinstance(jobs, list) or not jobs:
        return (
            "⚠️ Aucun résultat d'analyse disponible.\n"
            "Niveau indicatif : INDETERMINE."
        )

    abuse_score = None
    abuse_reports = None

    misp_uuids = set()
    misp_seen = False

    vt = {
        "malicious": None,
        "suspicious": None,
        "harmless": None,
        "undetected": None
    }

    warnings = []

    # 2. Lire chaque réponse.
    for job in jobs:
        if not isinstance(job, dict):
            warnings.append("Une réponse de job n'est pas un objet.")
            continue

        try:
            body = decode(job.get("body", job))
        except Exception:
            warnings.append("Le body d'un job est illisible.")
            continue

        if not isinstance(body, dict):
            warnings.append("Le body d'un job n'est pas un objet.")
            continue

        analyzer = str(
            body.get("analyzerName")
            or body.get("analyzerDefinition")
            or body.get("analyzerId")
            or "Analyseur inconnu"
        )

        # Vérifier le statut HTTP si la réponse contient un body.
        if "body" in job:
            http_status = number(job.get("status"))

            if http_status is None:
                warnings.append(f"{analyzer} : statut HTTP absent ou invalide.")
                continue

            if not 200 <= http_status < 300:
                warnings.append(f"{analyzer} : erreur HTTP {http_status}.")
                continue

        # Vérifier le statut du job.
        job_status = str(body.get("status") or "Unknown")

        if job_status != "Success":
            warnings.append(
                f"{analyzer} : job non exploitable, statut {job_status}."
            )
            continue

        try:
            # Vérifier le rapport.
            report = decode(body.get("report", {}))

            if not isinstance(report, dict):
                raise ValueError("Rapport absent ou invalide")

            if report.get("success") is False:
                warnings.append(
                    f"{analyzer} : le rapport indique un échec."
                )
                continue

            full = decode(report.get("full", {}))

            if not isinstance(full, dict):
                raise ValueError("Champ report.full absent ou invalide")

            name = analyzer.lower()

            # 3. AbuseIPDB
            if "abuseipdb" in name:
                values = full.get("values")

                if not isinstance(values, list) or not values:
                    raise ValueError("Champ values absent ou vide")

                local_score = None
                local_reports = None

                for entry in values:
                    if not isinstance(entry, dict):
                        raise ValueError("Entrée AbuseIPDB invalide")

                    data = decode(entry.get("data", {}))

                    if not isinstance(data, dict):
                        raise ValueError("Champ data AbuseIPDB invalide")

                    score = number(data.get("abuseConfidenceScore"))
                    reports = number(data.get("totalReports"))

                    if score is None or score > 100:
                        raise ValueError("Score AbuseIPDB absent ou invalide")

                    local_score = maximum(local_score, score)
                    local_reports = maximum(local_reports, reports)

                abuse_score = maximum(abuse_score, local_score)
                abuse_reports = maximum(abuse_reports, local_reports)

                if local_reports is None:
                    warnings.append(
                        f"{analyzer} : nombre de signalements absent."
                    )

            # 4. MISP
            elif "misp" in name:
                results = full.get("results")

                if not isinstance(results, list):
                    raise ValueError("Champ results absent ou invalide")

                local_uuids = set()

                for instance in results:
                    if not isinstance(instance, dict):
                        raise ValueError("Résultat d'instance MISP invalide")

                    events = instance.get("result")

                    if not isinstance(events, list):
                        raise ValueError("Liste result MISP non reconnue")

                    for event in events:
                        if not isinstance(event, dict):
                            raise ValueError("Événement MISP invalide")

                        uuid = event.get("uuid")

                        if not uuid:
                            raise ValueError("UUID d'événement MISP absent")

                        local_uuids.add(str(uuid))

                # Un tableau valide mais vide correspond à zéro résultat.
                misp_seen = True
                misp_uuids.update(local_uuids)

            # 5. VirusTotal
            elif "virustotal" in name:
                attributes = full.get("attributes")

                if not isinstance(attributes, dict):
                    raise ValueError("Champ attributes VirusTotal absent")

                stats = attributes.get("last_analysis_stats")

                if not isinstance(stats, dict):
                    raise ValueError("Statistiques VirusTotal absentes")

                parsed = {
                    key: number(stats.get(key))
                    for key in vt
                }

                if (
                    parsed["malicious"] is None
                    or parsed["suspicious"] is None
                ):
                    raise ValueError(
                        "Compteurs malicious/suspicious absents ou invalides"
                    )

                for key in vt:
                    vt[key] = maximum(vt[key], parsed[key])

                if any(value is None for value in parsed.values()):
                    warnings.append(
                        f"{analyzer} : certaines statistiques sont absentes."
                    )

            else:
                warnings.append(
                    f"{analyzer} : analyseur non traité par ce script."
                )

        except (ValueError, TypeError, AttributeError, SyntaxError) as exc:
            warnings.append(
                f"{analyzer} : format non reconnu ({exc})."
            )

    # 6. Calculer un niveau de triage indicatif.
    misp_count = len(misp_uuids) if misp_seen else None

    usable = any(
        value is not None
        for value in (
            abuse_score,
            misp_count,
            vt["malicious"],
            vt["suspicious"]
        )
    )

    if (
        (abuse_score is not None and abuse_score >= 50)
        or (vt["malicious"] or 0) > 0
        or (vt["suspicious"] or 0) > 0
    ):
        severity = "HIGH"
    elif (abuse_score or 0) > 0 or (misp_count or 0) > 0:
        severity = "MEDIUM"
    elif not usable or warnings:
        severity = "INDETERMINE"
    else:
        severity = "LOW — sur les résultats disponibles uniquement"

    # 7. Construire le résumé, sans répéter le titre Telegram.
    lines = [
        f"AbuseIPDB — score : {display(abuse_score)} / 100",
        f"AbuseIPDB — signalements : {display(abuse_reports)}",
        f"MISP — événements uniques : {display(misp_count)}",
        "VirusTotal :",
        f"  • Malveillants : {display(vt['malicious'])}",
        f"  • Suspects : {display(vt['suspicious'])}",
        f"  • Inoffensifs : {display(vt['harmless'])}",
        f"  • Non détectés : {display(vt['undetected'])}",
        "",
        f"Niveau indicatif : {severity}"
    ]

    if warnings:
        lines.append("\n⚠️ Analyses incomplètes ou non exploitables :")

        for warning in dict.fromkeys(warnings):
            lines.append(f"• {warning}")

    lines.append("\nN/A = donnée absente, pas un résultat à zéro.")

    return "\n".join(lines)


print(summarize())