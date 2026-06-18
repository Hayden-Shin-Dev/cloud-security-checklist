"""Security checklist data and scoring helpers for the Streamlit dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, TypedDict


@dataclass(frozen=True)
class CategoryMeta:
    """Metadata used to present a security control category."""

    name: str
    description: str
    owner: str


@dataclass(frozen=True)
class SecurityCheck:
    """A weighted cloud security checklist item."""

    id: str
    category: str
    title: str
    weight: int
    severity: str
    remediation_phase: str
    evidence_hint: str
    recommendation: str


class CategoryScore(TypedDict):
    """Calculated score information for a security category."""

    earned: int
    total: int
    score: int
    status: str


class Recommendation(TypedDict):
    """Remediation guidance for an unchecked security item."""

    category: str
    item: str
    severity: str
    remediation_phase: str
    weight: int
    evidence_hint: str
    recommendation: str


class AssessmentSummary(TypedDict):
    """Top-level assessment result values."""

    score: int
    risk_level: str
    checked_count: int
    unchecked_count: int
    critical_unchecked_count: int
    total_count: int


class SeverityBreakdown(TypedDict):
    """Selected and missing counts for a severity level."""

    selected: int
    missing: int
    total: int


CATEGORY_METADATA: tuple[CategoryMeta, ...] = (
    CategoryMeta(
        name="계정 및 접근 관리",
        description="관리자 접근, 사용자 계정, 권한 범위를 점검합니다.",
        owner="Security / IAM",
    ),
    CategoryMeta(
        name="네트워크 보안",
        description="외부 노출, 기본 차단 정책, 관리 포트 보호 수준을 점검합니다.",
        owner="Cloud Platform",
    ),
    CategoryMeta(
        name="데이터 보호",
        description="저장 데이터와 전송 데이터의 암호화 적용 상태를 점검합니다.",
        owner="Data / Platform",
    ),
    CategoryMeta(
        name="로그 및 모니터링",
        description="감사 로그 수집과 이상 접근 탐지 체계를 점검합니다.",
        owner="Security Operations",
    ),
    CategoryMeta(
        name="백업 및 운영 관리",
        description="복구 가능성, 환경 분리, 변경 통제 절차를 점검합니다.",
        owner="Operations",
    ),
)

CATEGORIES: tuple[str, ...] = tuple(category.name for category in CATEGORY_METADATA)

SEVERITY_RANK: dict[str, int] = {
    "Critical": 3,
    "High": 2,
    "Medium": 1,
}


SECURITY_CHECKS: tuple[SecurityCheck, ...] = (
    SecurityCheck(
        id="admin_mfa",
        category="계정 및 접근 관리",
        title="관리자 계정에 MFA가 적용되어 있다.",
        weight=10,
        severity="Critical",
        remediation_phase="즉시 조치",
        evidence_hint="관리자 계정 MFA 정책, 조건부 접근 정책, 예외 계정 목록",
        recommendation="모든 관리자 계정에 MFA를 필수로 적용하고 예외 계정은 별도 승인 및 정기 검토 대상으로 관리하세요.",
    ),
    SecurityCheck(
        id="individual_accounts",
        category="계정 및 접근 관리",
        title="사용자별 계정을 사용하고 공용 관리자 계정을 사용하지 않는다.",
        weight=6,
        severity="High",
        remediation_phase="단기 개선",
        evidence_hint="IAM 사용자 목록, 공유 계정 사용 이력, 관리자 그룹 멤버십",
        recommendation="개인별 계정을 발급하고 공용 관리자 계정은 비활성화하거나 비상 접근 절차로만 제한하세요.",
    ),
    SecurityCheck(
        id="least_privilege",
        category="계정 및 접근 관리",
        title="최소 권한 원칙이 적용되어 있다.",
        weight=8,
        severity="Critical",
        remediation_phase="즉시 조치",
        evidence_hint="역할 기반 권한 정책, 관리자 권한 부여 이력, 권한 검토 결과",
        recommendation="업무 역할별 권한 템플릿을 정의하고 관리자 권한은 필요한 기간에만 부여되도록 정기적으로 회수하세요.",
    ),
    SecurityCheck(
        id="default_deny",
        category="네트워크 보안",
        title="방화벽 또는 보안 그룹에 Default Deny 정책이 적용되어 있다.",
        weight=8,
        severity="Critical",
        remediation_phase="즉시 조치",
        evidence_hint="방화벽 정책, 보안 그룹 인바운드 규칙, 네트워크 ACL",
        recommendation="인바운드 기본 정책을 차단으로 설정하고 업무에 필요한 포트와 출발지만 명시적으로 허용하세요.",
    ),
    SecurityCheck(
        id="ssh_not_public",
        category="네트워크 보안",
        title="SSH 22번 포트가 전체 인터넷에 공개되어 있지 않다.",
        weight=7,
        severity="High",
        remediation_phase="단기 개선",
        evidence_hint="0.0.0.0/0 또는 ::/0 대상 SSH 허용 규칙",
        recommendation="SSH 접근은 VPN, Bastion Host, Zero Trust 접근 제어 또는 특정 관리 대역으로 제한하세요.",
    ),
    SecurityCheck(
        id="rdp_not_public",
        category="네트워크 보안",
        title="RDP 3389번 포트가 전체 인터넷에 공개되어 있지 않다.",
        weight=7,
        severity="High",
        remediation_phase="단기 개선",
        evidence_hint="0.0.0.0/0 또는 ::/0 대상 RDP 허용 규칙",
        recommendation="RDP는 인터넷 직접 노출을 제거하고 Bastion, JIT 접근, VPN 또는 관리형 원격 접속 서비스를 사용하세요.",
    ),
    SecurityCheck(
        id="db_not_public",
        category="네트워크 보안",
        title="데이터베이스가 인터넷에 직접 노출되어 있지 않다.",
        weight=8,
        severity="Critical",
        remediation_phase="즉시 조치",
        evidence_hint="공개 IP, 퍼블릭 엔드포인트, 데이터베이스 방화벽 허용 목록",
        recommendation="데이터베이스는 사설 네트워크에 배치하고 애플리케이션 계층 또는 허용된 관리 경로에서만 접근하도록 제한하세요.",
    ),
    SecurityCheck(
        id="data_encrypted_at_rest",
        category="데이터 보호",
        title="저장 데이터가 암호화되어 있다.",
        weight=7,
        severity="High",
        remediation_phase="단기 개선",
        evidence_hint="스토리지, 데이터베이스, 백업 저장소의 암호화 설정",
        recommendation="스토리지, 데이터베이스, 백업 저장소에 저장 데이터 암호화를 적용하고 키 관리 권한을 분리하세요.",
    ),
    SecurityCheck(
        id="data_encrypted_in_transit",
        category="데이터 보호",
        title="전송 데이터에 HTTPS 또는 TLS가 적용되어 있다.",
        weight=7,
        severity="High",
        remediation_phase="단기 개선",
        evidence_hint="TLS 인증서, 로드밸런서 리스너, 내부 API 통신 설정",
        recommendation="외부 및 내부 통신에 TLS를 적용하고 만료 예정 인증서와 취약한 프로토콜 사용 여부를 점검하세요.",
    ),
    SecurityCheck(
        id="logs_collected",
        category="로그 및 모니터링",
        title="시스템 로그와 접근 로그가 수집되고 있다.",
        weight=7,
        severity="High",
        remediation_phase="단기 개선",
        evidence_hint="중앙 로그 저장소, 감사 로그 수집 정책, 로그 보존 기간",
        recommendation="시스템, 네트워크, IAM, 애플리케이션 접근 로그를 중앙 로그 저장소로 수집하고 보존 기간을 정의하세요.",
    ),
    SecurityCheck(
        id="anomaly_alerts",
        category="로그 및 모니터링",
        title="비정상 접근에 대한 알림이 설정되어 있다.",
        weight=7,
        severity="High",
        remediation_phase="단기 개선",
        evidence_hint="알림 규칙, SIEM 탐지 정책, 관리자 로그인 실패 이벤트",
        recommendation="관리자 로그인 실패, 해외 접속, 권한 상승, 공개 설정 변경 같은 이벤트에 실시간 알림을 설정하세요.",
    ),
    SecurityCheck(
        id="regular_backups",
        category="백업 및 운영 관리",
        title="정기적인 데이터 백업이 설정되어 있다.",
        weight=6,
        severity="Medium",
        remediation_phase="운영 개선",
        evidence_hint="백업 정책, 백업 성공 이력, 보존 기간 설정",
        recommendation="핵심 데이터와 설정 자산에 정기 백업 정책을 적용하고 백업 실패 알림을 운영 절차에 포함하세요.",
    ),
    SecurityCheck(
        id="restore_tests",
        category="백업 및 운영 관리",
        title="백업 데이터의 복구 테스트를 수행하고 있다.",
        weight=5,
        severity="Medium",
        remediation_phase="운영 개선",
        evidence_hint="복구 테스트 결과, RTO/RPO 검증 기록, 장애 대응 훈련 이력",
        recommendation="정기적으로 복구 리허설을 수행해 RTO와 RPO를 검증하고 결과를 운영 개선 항목으로 관리하세요.",
    ),
    SecurityCheck(
        id="environment_separation",
        category="백업 및 운영 관리",
        title="운영 환경과 개발 환경이 분리되어 있다.",
        weight=4,
        severity="Medium",
        remediation_phase="운영 개선",
        evidence_hint="계정, 네트워크, 데이터, 배포 권한의 환경별 분리 구조",
        recommendation="운영과 개발 환경의 계정, 네트워크, 데이터, 배포 권한을 분리하고 운영 데이터 반출을 통제하세요.",
    ),
    SecurityCheck(
        id="change_approval",
        category="백업 및 운영 관리",
        title="중요 보안 설정 변경에 대한 승인 절차가 존재한다.",
        weight=3,
        severity="Medium",
        remediation_phase="운영 개선",
        evidence_hint="변경 승인 기록, 접근 권한 변경 이력, 보안 설정 변경 티켓",
        recommendation="방화벽, IAM, 암호화, 로깅 같은 핵심 보안 설정 변경은 승인, 기록, 사후 검토 절차를 거치게 하세요.",
    ),
)


def get_total_weight(checks: Iterable[SecurityCheck] = SECURITY_CHECKS) -> int:
    """Return the total weight for the provided checklist items."""

    return sum(check.weight for check in checks)


def calculate_score(selected_ids: Iterable[str]) -> int:
    """Calculate the overall security score as an integer out of 100."""

    selected = set(selected_ids)
    total_weight = get_total_weight()
    earned_weight = sum(check.weight for check in SECURITY_CHECKS if check.id in selected)

    if total_weight == 0:
        return 0

    return round((earned_weight / total_weight) * 100)


def get_risk_level(score: int) -> str:
    """Return a Korean risk level label for a calculated score."""

    if score >= 80:
        return "양호"
    if score >= 60:
        return "주의"
    if score >= 40:
        return "위험"
    return "매우 위험"


def get_category_status(score: int) -> str:
    """Return a compact category status label for a percentage score."""

    if score >= 80:
        return "관리됨"
    if score >= 60:
        return "개선 필요"
    if score >= 40:
        return "취약"
    return "우선 조치"


def calculate_category_scores(selected_ids: Iterable[str]) -> dict[str, CategoryScore]:
    """Calculate earned, total, and percentage scores for each category."""

    selected = set(selected_ids)
    result: dict[str, CategoryScore] = {}

    for category in CATEGORIES:
        category_checks = [check for check in SECURITY_CHECKS if check.category == category]
        total = get_total_weight(category_checks)
        earned = sum(check.weight for check in category_checks if check.id in selected)
        score = round((earned / total) * 100) if total else 0
        result[category] = {
            "earned": earned,
            "total": total,
            "score": score,
            "status": get_category_status(score),
        }

    return result


def generate_recommendations(selected_ids: Iterable[str]) -> list[Recommendation]:
    """Generate remediation recommendations for unchecked checklist items."""

    selected = set(selected_ids)
    recommendations = [
        {
            "category": check.category,
            "item": check.title,
            "severity": check.severity,
            "remediation_phase": check.remediation_phase,
            "weight": check.weight,
            "evidence_hint": check.evidence_hint,
            "recommendation": check.recommendation,
        }
        for check in SECURITY_CHECKS
        if check.id not in selected
    ]
    return sorted(
        recommendations,
        key=lambda item: (SEVERITY_RANK[item["severity"]], item["weight"]),
        reverse=True,
    )


def build_assessment_summary(selected_ids: Iterable[str]) -> AssessmentSummary:
    """Build a top-level assessment summary for the selected controls."""

    selected = set(selected_ids)
    score = calculate_score(selected)
    unchecked = [check for check in SECURITY_CHECKS if check.id not in selected]
    critical_unchecked_count = sum(1 for check in unchecked if check.severity == "Critical")

    return {
        "score": score,
        "risk_level": get_risk_level(score),
        "checked_count": len(selected),
        "unchecked_count": len(unchecked),
        "critical_unchecked_count": critical_unchecked_count,
        "total_count": len(SECURITY_CHECKS),
    }


def calculate_severity_breakdown(selected_ids: Iterable[str]) -> dict[str, SeverityBreakdown]:
    """Calculate selected and missing control counts by severity."""

    selected = set(selected_ids)
    result: dict[str, SeverityBreakdown] = {}

    for severity in SEVERITY_RANK:
        controls = [check for check in SECURITY_CHECKS if check.severity == severity]
        selected_count = sum(1 for check in controls if check.id in selected)
        total = len(controls)
        result[severity] = {
            "selected": selected_count,
            "missing": total - selected_count,
            "total": total,
        }

    return result
