from app.backend.adapters.base import LookupResponse
from app.backend.thresholds import (
    EPSS_HIGH,
    MALICIOUS_SOURCE_SCORE,
    SUMMARY_CAUTION,
    SUMMARY_NO_THREAT,
    SUMMARY_SIGNIFICANT,
)


def generate_executive_summary(response: LookupResponse) -> str:
    c = response.composite
    score = c.score
    verdict = c.verdict
    confidence = c.confidence
    assessment = response.final_assessment
    if assessment is not None:
        return _assessment_summary(response, assessment)[:1800]
    ss = score
    sentences = []

    ss_label = f"{ss}/100"
    sentences.append(
        f"The indicator {response.normalized} ({response.ioc_type}) received a composite score of {ss_label}, resulting in a verdict of {verdict} with {confidence} confidence."
    )

    malicious = [sw for sw in c.source_breakdown if sw.verdict == "malicious" and sw.score and sw.score >= MALICIOUS_SOURCE_SCORE]
    suspicious = [sw for sw in c.source_breakdown if sw.verdict == "suspicious"]
    clean = [sw for sw in c.source_breakdown if sw.verdict == "clean"]

    factors = []
    if malicious:
        names = [sw.name for sw in malicious[:3]]
        factors.append(f"flagged as malicious by {_join_names(names)}")
    if suspicious and not malicious:
        names = [sw.name for sw in suspicious[:2]]
        factors.append(f"marked suspicious by {_join_names(names)}")
    if clean:
        names = [sw.name for sw in clean[:2]]
        factors.append(f"reported clean by {_join_names(names)}")

    if factors:
        sentences.append("Key contributing sources: " + "; ".join(factors) + ".")

    cve_info = response.enrichment.cve if response.enrichment else None
    if cve_info and cve_info.is_in_kev:
        sentences.append(
            "This CVE is listed in the CISA Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild."
        )
    elif cve_info and cve_info.epss_score and cve_info.epss_score >= EPSS_HIGH:
        sentences.append(
            f"The CVE has a high EPSS exploit probability of {cve_info.epss_score*100:.1f}%, suggesting active exploitation is likely."
        )

    breach_info = response.enrichment.breach if response.enrichment else None
    if breach_info and breach_info.breach_count and breach_info.breach_count > 0:
        sentences.append(
            f"Associated with {breach_info.breach_count} known data {'breaches' if breach_info.breach_count > 1 else 'breach'}, indicating prior compromise exposure."
        )

    if not response.results and response.enrichment and response.enrichment.extra:
        sentences.append(
            "No reputation provider currently covers this IOC type; the result contains contextual enrichment and should not be interpreted as clean."
        )

    if score >= SUMMARY_SIGNIFICANT and verdict == "malicious":
        sentences.append("This indicator presents a significant threat and should be blocked or monitored closely.")
    elif score >= SUMMARY_CAUTION and verdict in ("malicious", "suspicious"):
        sentences.append("This indicator warrants further investigation and caution.")
    elif score < SUMMARY_NO_THREAT and verdict == "clean":
        sentences.append("No threat indicators were identified for this indicator at this time.")

    if len(sentences) > 4:
        sentences = sentences[:4]

    return " ".join(sentences)


def _review_sentence(assessment) -> str:
    reasons = [reason.rstrip(".") for reason in (assessment.review_reasons or []) if reason]
    if not (assessment.needs_review or assessment.analyst_review_recommended) or not reasons:
        return ""
    return "Analyst review: " + "; ".join(reasons[:2]) + "."


def _assessment_summary(response: LookupResponse, assessment) -> str:
    """Summary built only from the final assessment, so the headline, score,
    reason and review notes can never disagree with the verdict badge."""
    ioc = response.normalized
    domain = assessment.assessment_domain
    verdict = assessment.final_verdict
    confidence = assessment.confidence
    score = assessment.normalized_score
    if domain == "vulnerability":
        cvss = assessment.evidence_summary.get("cvss_score") if assessment.evidence_summary else None
        headline = (
            f"{ioc} is a {verdict}-severity vulnerability (vulnerability risk {score:g}/100, {confidence} confidence)."
            if cvss is not None
            else f"{ioc} has no CVSS severity yet (classified {verdict}; vulnerability risk {score:g}/100, {confidence} confidence)."
        )
        return " ".join(part for part in (headline, assessment.reason, _review_sentence(assessment)) if part)
    if domain == "attack_technique":
        technique = assessment.techniques[0] if assessment.techniques else {}
        technique_id = technique.get("technique_id") or technique.get("id") or ioc
        technique_name = technique.get("name")
        label = f"{technique_id} ({technique_name})" if technique_name else str(technique_id)
        return f"ATT&CK technique {label} is classified as {verdict} with {confidence} confidence. {assessment.reason}"
    if domain == "security_test_artifact":
        return f"{ioc} is the EICAR security test artifact. Its antivirus detections are intentional test behavior, not evidence of live malware."
    if domain in {"credential_exposure", "identity_reputation"} and response.ioc_type in {"email", "username", "password"}:
        label = {
            "breached": "exposed in breach or infostealer data",
            "not_breached": "not found in the breach and infostealer sources that answered",
            "suspicious": "suspicious (identity abuse reputation, no credential exposure found)",
        }.get(verdict, verdict)
        headline = f"{ioc} ({response.ioc_type}) is {label}; risk score {score:g}/100 with {confidence} confidence."
        action = "Reset the credential and enforce MFA for the affected account." if verdict == "breached" else ""
        return " ".join(part for part in (headline, assessment.reason, _review_sentence(assessment), action) if part)
    if domain != "ioc_reputation":
        return (
            f"{ioc} is assessed in the {domain.replace('_', ' ')} domain as {verdict} with {confidence} confidence. "
            f"{assessment.reason}"
        )

    sentences = [
        f"The indicator {ioc} ({response.ioc_type}) received a risk score of {score:g}/100, resulting in a verdict of {verdict} with {confidence} confidence.",
        assessment.reason,
    ]
    review = _review_sentence(assessment)
    if review:
        sentences.append(review)
    if verdict == "malicious" and score >= SUMMARY_SIGNIFICANT:
        sentences.append("This indicator presents a significant threat and should be blocked or monitored closely.")
    elif verdict in ("malicious", "suspicious") and score >= SUMMARY_CAUTION:
        sentences.append("This indicator warrants further investigation and caution.")
    elif verdict == "suspicious":
        sentences.append("The evidence is weak or indirect; investigate before acting on it.")
    elif verdict == "benign" and score < SUMMARY_NO_THREAT:
        sentences.append("No threat indicators were identified for this indicator at this time.")
    elif verdict == "unknown":
        sentences.append("Treat this indicator as unassessed, not as clean.")
    return " ".join(sentences)


def _join_names(names: list[str]) -> str:
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + f", and {names[-1]}"
