"""Streamlit interface for the Cloud Security Checklist dashboard."""

from __future__ import annotations

from datetime import date
from html import escape
from typing import Any

import pandas as pd
import streamlit as st

from security_checks import (
    CATEGORIES,
    CATEGORY_METADATA,
    SECURITY_CHECKS,
    build_assessment_summary,
    calculate_category_scores,
    calculate_severity_breakdown,
    generate_recommendations,
    get_risk_message,
)


CLOUD_ENVIRONMENTS: tuple[str, ...] = ("Azure", "AWS", "GCP", "On-Premise")
ASSESSMENT_SCOPES: tuple[str, ...] = ("운영 환경", "개발/검증 환경", "전사 공통", "신규 구축")
RISK_APPETITES: tuple[str, ...] = ("보수적", "표준", "공격적")
CHECKBOX_PREFIX = "security_check_"
CREATOR_NAME = "Hayden Shin"
BUG_REPORT_EMAIL = "shinminchuhl@gmail.com"

RISK_STYLES: dict[str, dict[str, str]] = {
    "양호": {"bg": "#E8F5E9", "fg": "#1B5E20", "border": "#A5D6A7"},
    "주의": {"bg": "#FFF8E1", "fg": "#7A4F01", "border": "#FFE082"},
    "위험": {"bg": "#FFF3E0", "fg": "#8A3B00", "border": "#FFB74D"},
    "매우 위험": {"bg": "#FFEBEE", "fg": "#8B1A1A", "border": "#EF9A9A"},
}

SEVERITY_STYLES: dict[str, dict[str, str]] = {
    "Critical": {"bg": "#FEE2E2", "fg": "#991B1B"},
    "High": {"bg": "#FFEDD5", "fg": "#9A3412"},
    "Medium": {"bg": "#FEF3C7", "fg": "#92400E"},
}


def configure_page() -> None:
    """Configure the page and inject dashboard styles."""

    st.set_page_config(
        page_title="Cloud Security Checklist",
        page_icon="C",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(
        """
        <style>
        :root {
            color-scheme: light;
            --app-bg: #F3F6FA;
            --sidebar-bg: #F8FAFC;
            --surface: #FFFFFF;
            --surface-muted: #F8FAFC;
            --surface-soft: #EEF4FF;
            --ink: #111827;
            --ink-strong: #0F172A;
            --muted: #64748B;
            --line: #D6DCE6;
            --line-strong: #B8C2D2;
            --brand: #1D4ED8;
            --brand-strong: #1E3A8A;
            --accent: #0F766E;
            --success: #15803D;
            --warning: #B45309;
            --danger: #B91C1C;
            --shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
            --card-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
        }
        @media (prefers-color-scheme: dark) {
            :root {
                color-scheme: dark;
                --app-bg: #0B1020;
                --sidebar-bg: #0F172A;
                --surface: #111827;
                --surface-muted: #162033;
                --surface-soft: #172554;
                --ink: #E5E7EB;
                --ink-strong: #F8FAFC;
                --muted: #A7B0C0;
                --line: #263244;
                --line-strong: #3A485F;
                --brand: #60A5FA;
                --brand-strong: #93C5FD;
                --accent: #2DD4BF;
                --success: #86EFAC;
                --warning: #FBBF24;
                --danger: #FCA5A5;
                --shadow: 0 12px 34px rgba(0, 0, 0, 0.36);
                --card-shadow: 0 1px 2px rgba(0, 0, 0, 0.28);
            }
        }
        .stApp {
            background: var(--app-bg);
            color: var(--ink);
        }
        header[data-testid="stHeader"] {
            background: transparent;
        }
        .block-container {
            padding: 1.35rem 1.8rem 2.5rem;
            max-width: 1440px;
        }
        section[data-testid="stSidebar"] {
            background: var(--sidebar-bg);
            border-right: 1px solid var(--line);
        }
        section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"],
        section[data-testid="stSidebar"] label,
        section[data-testid="stSidebar"] p {
            color: var(--ink);
        }
        .dashboard-header {
            border-bottom: 1px solid var(--line);
            margin-bottom: 1.2rem;
            padding: 0.35rem 0 1.05rem;
        }
        .header-main {
            align-items: flex-start;
            display: flex;
            gap: 1.25rem;
            justify-content: space-between;
        }
        .dashboard-eyebrow {
            color: var(--brand);
            font-size: 0.78rem;
            font-weight: 780;
            letter-spacing: 0.08em;
            margin-bottom: 0.3rem;
            text-transform: uppercase;
        }
        .dashboard-title {
            color: var(--ink-strong);
            font-size: 2.15rem;
            font-weight: 760;
            letter-spacing: 0;
            margin-bottom: 0.25rem;
        }
        .dashboard-subtitle {
            color: var(--muted);
            font-size: 0.98rem;
            line-height: 1.55;
            max-width: 980px;
            margin-bottom: 0.6rem;
        }
        .header-meta {
            align-items: flex-end;
            display: flex;
            flex-direction: column;
            gap: 0.45rem;
            min-width: 220px;
            padding-top: 0.15rem;
            text-align: right;
        }
        .creator-line {
            color: var(--muted);
            font-size: 0.88rem;
            font-weight: 650;
        }
        .creator-line strong {
            color: var(--ink-strong);
        }
        .contact-pill {
            background: var(--surface-soft);
            border: 1px solid var(--line);
            border-radius: 999px;
            color: var(--brand-strong);
            display: inline-flex;
            font-size: 0.8rem;
            font-weight: 720;
            padding: 0.35rem 0.65rem;
            text-decoration: none;
            white-space: nowrap;
        }
        .footer-notice {
            border-top: 1px solid var(--line);
            color: var(--muted);
            font-size: 0.84rem;
            margin-top: 1.5rem;
            padding-top: 0.9rem;
        }
        .status-strip {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 0.7rem;
            margin: 0.95rem 0 0;
        }
        .strip-item,
        .metric-card,
        .insight-panel,
        .category-card {
            background: var(--surface);
            border: 1px solid var(--line);
            border-radius: 8px;
            box-shadow: var(--card-shadow);
        }
        .strip-item {
            padding: 0.72rem 0.85rem;
        }
        .strip-label {
            color: var(--muted);
            font-size: 0.76rem;
            font-weight: 680;
            text-transform: uppercase;
            margin-bottom: 0.15rem;
        }
        .strip-value {
            color: var(--ink-strong);
            font-size: 0.96rem;
            font-weight: 680;
            overflow-wrap: anywhere;
        }
        .executive-grid {
            display: grid;
            gap: 0.85rem;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            margin-bottom: 0.75rem;
        }
        .metric-card {
            min-height: 142px;
            padding: 1rem 1.05rem;
            border-top: 3px solid var(--brand);
        }
        .metric-card.warning {
            border-top-color: var(--warning);
        }
        .metric-card.danger {
            border-top-color: var(--danger);
        }
        .metric-card.success {
            border-top-color: var(--success);
        }
        .metric-label {
            color: var(--muted);
            font-size: 0.82rem;
            font-weight: 700;
            margin-bottom: 0.45rem;
        }
        .metric-value-row {
            align-items: baseline;
            display: flex;
            gap: 0.35rem;
        }
        .metric-value {
            color: var(--ink-strong);
            font-size: 2.35rem;
            font-weight: 780;
            line-height: 1;
        }
        .metric-unit {
            color: var(--muted);
            font-size: 0.92rem;
            font-weight: 650;
        }
        .metric-help {
            color: var(--muted);
            font-size: 0.82rem;
            margin-top: 0.5rem;
        }
        .risk-badge,
        .severity-badge {
            display: inline-flex;
            align-items: center;
            border-radius: 6px;
            font-weight: 760;
            white-space: nowrap;
        }
        .risk-badge {
            border: 1px solid;
            padding: 0.45rem 0.7rem;
            font-size: 1.05rem;
        }
        .severity-badge {
            padding: 0.22rem 0.48rem;
            font-size: 0.72rem;
        }
        .insight-panel {
            padding: 1rem;
            margin: 0.7rem 0 1rem;
        }
        .insight-title {
            color: var(--ink-strong);
            font-size: 1rem;
            font-weight: 750;
            margin-bottom: 0.35rem;
        }
        .insight-copy {
            color: var(--muted);
            font-size: 0.92rem;
            line-height: 1.55;
        }
        .category-card {
            padding: 0.9rem;
            margin-bottom: 0.75rem;
        }
        .category-head {
            display: flex;
            justify-content: space-between;
            gap: 0.8rem;
            align-items: flex-start;
            margin-bottom: 0.45rem;
        }
        .category-name {
            color: var(--ink-strong);
            font-weight: 760;
            font-size: 0.96rem;
        }
        .category-owner {
            color: var(--muted);
            font-size: 0.76rem;
            margin-top: 0.15rem;
        }
        .category-score {
            color: var(--brand);
            font-size: 1.1rem;
            font-weight: 780;
            text-align: right;
        }
        .score-track {
            background: var(--surface-muted);
            border: 1px solid var(--line);
            border-radius: 999px;
            height: 9px;
            margin-top: 0.65rem;
            overflow: hidden;
        }
        .score-fill {
            background: linear-gradient(90deg, var(--brand), var(--accent));
            border-radius: 999px;
            height: 100%;
        }
        .small-muted {
            color: var(--muted);
            font-size: 0.86rem;
            line-height: 1.45;
        }
        div[data-testid="stProgress"] > div > div > div > div {
            background-color: var(--brand);
        }
        .stButton > button,
        .stDownloadButton > button {
            border-radius: 6px;
            border: 1px solid var(--line-strong);
            font-weight: 680;
        }
        div[data-testid="stDataFrame"] {
            border: 1px solid var(--line);
            border-radius: 8px;
            overflow: hidden;
        }
        div[data-testid="stDataFrame"] * {
            color-scheme: light dark;
        }
        div[data-testid="stTabs"] button {
            font-weight: 700;
        }
        @media (max-width: 900px) {
            .block-container {
                padding-left: 1rem;
                padding-right: 1rem;
            }
            .status-strip {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .metric-value {
                font-size: 2rem;
            }
            .executive-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 560px) {
            .status-strip {
                grid-template-columns: 1fr;
            }
            .executive-grid {
                grid-template-columns: 1fr;
            }
            .dashboard-title {
                font-size: 1.7rem;
            }
            .header-main {
                display: block;
            }
            .header-meta {
                align-items: flex-start;
                margin-top: 0.75rem;
                min-width: 0;
                text-align: left;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def initialize_check_state() -> None:
    """Create default checkbox values in session state."""

    for check in SECURITY_CHECKS:
        st.session_state.setdefault(f"{CHECKBOX_PREFIX}{check.id}", False)


def set_all_checks(value: bool) -> None:
    """Set every checklist checkbox to the same value."""

    for check in SECURITY_CHECKS:
        st.session_state[f"{CHECKBOX_PREFIX}{check.id}"] = value


def get_selected_check_ids() -> list[str]:
    """Return IDs for the checklist items selected by the user."""

    return [
        check.id
        for check in SECURITY_CHECKS
        if st.session_state.get(f"{CHECKBOX_PREFIX}{check.id}", False)
    ]


def render_badge(text: str, style: dict[str, str], *, class_name: str) -> str:
    """Return a small HTML badge with inline colors."""

    border = style.get("border", style["bg"])
    return (
        f"<span class='{class_name}' "
        f"style='background:{style['bg']};color:{style['fg']};border-color:{border};'>"
        f"{text}</span>"
    )


def safe_html(value: object) -> str:
    """Escape a value before inserting it into an HTML snippet."""

    return escape(str(value), quote=True)


def build_export_filename(metadata: dict[str, str | date]) -> str:
    """Build a stable CSV filename from the assessment metadata."""

    checked_date = metadata["checked_date"]
    environment = str(metadata["cloud_environment"]).lower().replace("-", "_")
    scope = str(metadata["assessment_scope"]).replace("/", "_").replace(" ", "_")
    return f"cloud_security_checklist_{environment}_{scope}_{checked_date}.csv"


def render_sidebar() -> dict[str, str | date]:
    """Render assessment controls and return metadata."""

    with st.sidebar:
        st.header("점검 설정")
        st.subheader("대상 정보")
        organization_name = st.text_input(
            "회사명 또는 프로젝트명",
            placeholder="예: ABC Cloud Migration",
        ).strip()
        assessor_name = st.text_input(
            "점검 담당자",
            placeholder="예: Cloud Security Team",
        ).strip()
        cloud_environment = st.selectbox("클라우드 환경", CLOUD_ENVIRONMENTS)
        assessment_scope = st.selectbox("점검 범위", ASSESSMENT_SCOPES)
        risk_appetite = st.selectbox("위험 수용 기준", RISK_APPETITES, index=1)
        assessment_note = st.text_area(
            "점검 메모",
            placeholder="예: 운영 구독 기준 1차 자체 점검",
            height=84,
        ).strip()
        checked_date = date.today()
        st.caption(f"점검일: {checked_date.isoformat()}")

        st.divider()
        st.subheader("점검 제어")
        select_col, reset_col = st.columns(2)
        with select_col:
            if st.button("전체 선택", use_container_width=True):
                set_all_checks(True)
        with reset_col:
            if st.button("초기화", use_container_width=True):
                set_all_checks(False)

    return {
        "organization_name": organization_name or "미입력",
        "assessor_name": assessor_name or "미입력",
        "cloud_environment": cloud_environment,
        "assessment_scope": assessment_scope,
        "risk_appetite": risk_appetite,
        "assessment_note": assessment_note or "미입력",
        "checked_date": checked_date,
    }


def build_export_dataframe(
    *,
    metadata: dict[str, str | date],
    selected_ids: list[str],
    score: int,
    risk_level: str,
) -> pd.DataFrame:
    """Build a CSV-friendly assessment result table."""

    selected = set(selected_ids)
    rows: list[dict[str, Any]] = []

    for check in SECURITY_CHECKS:
        is_checked = check.id in selected
        rows.append(
            {
                "점검일": metadata["checked_date"],
                "회사명 또는 프로젝트명": metadata["organization_name"],
                "점검 담당자": metadata["assessor_name"],
                "클라우드 환경": metadata["cloud_environment"],
                "점검 범위": metadata["assessment_scope"],
                "위험 수용 기준": metadata["risk_appetite"],
                "점검 메모": metadata["assessment_note"],
                "카테고리": check.category,
                "심각도": check.severity,
                "개선 단계": check.remediation_phase,
                "점검 항목": check.title,
                "적용 여부": "Y" if is_checked else "N",
                "가중치": check.weight,
                "획득 점수": check.weight if is_checked else 0,
                "증적 힌트": check.evidence_hint,
                "개선 권고사항": "" if is_checked else check.recommendation,
                "총 보안 점수": score,
                "위험 등급": risk_level,
            }
        )

    return pd.DataFrame(rows)


def render_header(metadata: dict[str, str | date]) -> None:
    """Render dashboard title and assessment metadata strip."""

    organization = safe_html(metadata["organization_name"])
    environment = safe_html(metadata["cloud_environment"])
    scope = safe_html(metadata["assessment_scope"])
    risk_appetite = safe_html(metadata["risk_appetite"])
    checked_date = safe_html(metadata["checked_date"])

    st.markdown(
        f"""
        <div class='dashboard-header'>
            <div class='header-main'>
                <div>
                    <div class='dashboard-eyebrow'>Security Operations Workspace</div>
                    <div class='dashboard-title'>Cloud Security Checklist</div>
                    <div class='dashboard-subtitle'>
                    클라우드 보안 통제 적용 상태와 개선 우선순위를 점검하는 비즈니스 보안 대시보드입니다.
                    </div>
                </div>
                <div class='header-meta'>
                    <div class='creator-line'>Created by <strong>{CREATOR_NAME}</strong></div>
                    <a class='contact-pill' href='mailto:{BUG_REPORT_EMAIL}'>Bug reports: {BUG_REPORT_EMAIL}</a>
                </div>
            </div>
            <div class='status-strip'>
                <div class='strip-item'>
                    <div class='strip-label'>Organization</div>
                    <div class='strip-value'>{organization}</div>
                </div>
                <div class='strip-item'>
                    <div class='strip-label'>Environment</div>
                    <div class='strip-value'>{environment}</div>
                </div>
                <div class='strip-item'>
                    <div class='strip-label'>Scope</div>
                    <div class='strip-value'>{scope}</div>
                </div>
                <div class='strip-item'>
                    <div class='strip-label'>Risk Appetite</div>
                    <div class='strip-value'>{risk_appetite}</div>
                </div>
                <div class='strip-item'>
                    <div class='strip-label'>Assessment Date</div>
                    <div class='strip-value'>{checked_date}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_footer() -> None:
    """Render ownership notice at the bottom of the dashboard."""

    st.markdown(
        f"""
        <div class='footer-notice'>
        Cloud Security Checklist was created and maintained by <strong>{CREATOR_NAME}</strong>.
        For bug reports, contact {BUG_REPORT_EMAIL}.
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_score_cards(summary: dict[str, int | str]) -> None:
    """Render executive KPI cards."""

    risk_level = str(summary["risk_level"])
    risk_badge = render_badge(risk_level, RISK_STYLES[risk_level], class_name="risk-badge")
    completion = round((int(summary["checked_count"]) / int(summary["total_count"])) * 100)

    st.markdown(
        f"""
        <div class='executive-grid'>
            <div class='metric-card'>
                <div class='metric-label'>Security Score</div>
                <div class='metric-value-row'>
                    <div class='metric-value'>{summary['score']}</div>
                    <div class='metric-unit'>/ 100</div>
                </div>
                <div class='metric-help'>가중치 기반 총점</div>
            </div>
            <div class='metric-card success'>
                <div class='metric-label'>Risk Rating</div>
                {risk_badge}
                <div class='metric-help'>점수 구간 기준 자동 산정</div>
            </div>
            <div class='metric-card warning'>
                <div class='metric-label'>Open Gaps</div>
                <div class='metric-value-row'>
                    <div class='metric-value'>{summary['unchecked_count']}</div>
                    <div class='metric-unit'>items</div>
                </div>
                <div class='metric-help'>미충족 통제 항목</div>
            </div>
            <div class='metric-card danger'>
                <div class='metric-label'>Critical Gaps</div>
                <div class='metric-value-row'>
                    <div class='metric-value'>{summary['critical_unchecked_count']}</div>
                    <div class='metric-unit'>items</div>
                </div>
                <div class='metric-help'>우선 조치 대상</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.progress(int(summary["score"]) / 100)
    st.caption(f"통제 적용률 {completion}% | {summary['checked_count']} / {summary['total_count']} 항목 충족")


def render_executive_note(summary: dict[str, int | str]) -> None:
    """Render a concise executive interpretation."""

    score = int(summary["score"])
    risk_level = str(summary["risk_level"])
    message = get_risk_message(score)

    st.markdown(
        f"""
        <div class='insight-panel'>
            <div class='insight-title'>Executive Summary | {risk_level}</div>
            <div class='insight-copy'>{message}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_category_cards(selected_ids: list[str]) -> None:
    """Render category score cards with progress bars."""

    category_scores = calculate_category_scores(selected_ids)
    for meta in CATEGORY_METADATA:
        values = category_scores[meta.name]
        st.markdown(
            f"""
            <div class='category-card'>
                <div class='category-head'>
                    <div>
                        <div class='category-name'>{meta.name}</div>
                        <div class='category-owner'>{meta.owner}</div>
                    </div>
                    <div>
                        <div class='category-score'>{values['score']}점</div>
                        <div class='small-muted'>{values['status']}</div>
                    </div>
                </div>
                <div class='small-muted'>{meta.description}</div>
                <div class='score-track'>
                    <div class='score-fill' style='width:{values['score']}%;'></div>
                </div>
                <div class='small-muted'>{values['earned']} / {values['total']} weighted points</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_category_table(selected_ids: list[str]) -> None:
    """Render category scores in a compact table."""

    rows = []
    category_scores = calculate_category_scores(selected_ids)
    for meta in CATEGORY_METADATA:
        values = category_scores[meta.name]
        rows.append(
            {
                "카테고리": meta.name,
                "담당 영역": meta.owner,
                "획득 점수": values["earned"],
                "총 가중치": values["total"],
                "점수": values["score"],
                "상태": values["status"],
            }
        )
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)


def render_category_chart(selected_ids: list[str]) -> None:
    """Render a simple category score chart."""

    category_scores = calculate_category_scores(selected_ids)
    chart_df = pd.DataFrame(
        {
            "카테고리": list(category_scores.keys()),
            "점수": [values["score"] for values in category_scores.values()],
        }
    ).set_index("카테고리")
    st.bar_chart(chart_df, use_container_width=True)


def render_severity_breakdown(selected_ids: list[str]) -> None:
    """Render selected and missing controls by severity."""

    rows = []
    breakdown = calculate_severity_breakdown(selected_ids)
    for severity, values in breakdown.items():
        rows.append(
            {
                "심각도": severity,
                "충족": values["selected"],
                "미충족": values["missing"],
                "전체": values["total"],
            }
        )
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)


def render_checklist() -> None:
    """Render checklist controls grouped by category."""

    selected_categories = st.multiselect(
        "카테고리 필터",
        options=CATEGORIES,
        default=list(CATEGORIES),
    )
    if not selected_categories:
        st.info("표시할 카테고리를 하나 이상 선택하세요.")
        return

    for meta in CATEGORY_METADATA:
        if meta.name not in selected_categories:
            continue
        with st.expander(f"{meta.name} | {meta.owner}", expanded=True):
            st.caption(meta.description)
            checks = [check for check in SECURITY_CHECKS if check.category == meta.name]
            for check in checks:
                label_col, info_col = st.columns([4, 1])
                with label_col:
                    st.checkbox(
                        check.title,
                        key=f"{CHECKBOX_PREFIX}{check.id}",
                        help=check.evidence_hint,
                    )
                with info_col:
                    severity_badge = render_badge(
                        check.severity,
                        SEVERITY_STYLES[check.severity],
                        class_name="severity-badge",
                    )
                    st.markdown(severity_badge, unsafe_allow_html=True)
                    st.caption(f"{check.weight}점")


def render_control_catalog() -> None:
    """Render all controls as a reference catalog."""

    rows = [
        {
            "카테고리": check.category,
            "심각도": check.severity,
            "개선 단계": check.remediation_phase,
            "가중치": check.weight,
            "점검 항목": check.title,
            "확인 증적": check.evidence_hint,
        }
        for check in SECURITY_CHECKS
    ]
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)


def render_risk_register(selected_ids: list[str]) -> None:
    """Render unchecked controls and recommendations."""

    recommendations = generate_recommendations(selected_ids)
    if not recommendations:
        st.success("미충족 항목이 없습니다. 현재 통제 수준을 유지하고 정기 점검 주기를 운영하세요.")
        return

    severity_filter = st.multiselect(
        "심각도 필터",
        options=list(SEVERITY_STYLES.keys()),
        default=list(SEVERITY_STYLES.keys()),
    )
    filtered_recommendations = [
        item for item in recommendations if item["severity"] in severity_filter
    ]
    if not filtered_recommendations:
        st.info("선택한 심각도 조건에 해당하는 위험 요소가 없습니다.")
        return

    rows = [
        {
            "우선순위": index,
            "카테고리": item["category"],
            "심각도": item["severity"],
            "개선 단계": item["remediation_phase"],
            "가중치": item["weight"],
            "위험 요소": item["item"],
            "권고사항": item["recommendation"],
            "증적 힌트": item["evidence_hint"],
        }
        for index, item in enumerate(filtered_recommendations, start=1)
    ]
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

    st.subheader("우선 조치 항목")
    for item in filtered_recommendations[:5]:
        with st.expander(f"{item['severity']} | {item['remediation_phase']} | {item['item']}", expanded=False):
            st.write(item["recommendation"])
            st.caption(f"확인 증적: {item['evidence_hint']}")


def render_export_panel(
    *,
    metadata: dict[str, str | date],
    selected_ids: list[str],
    summary: dict[str, int | str],
) -> None:
    """Render export preview and CSV download button."""

    export_df = build_export_dataframe(
        metadata=metadata,
        selected_ids=selected_ids,
        score=int(summary["score"]),
        risk_level=str(summary["risk_level"]),
    )
    st.dataframe(export_df, hide_index=True, use_container_width=True)

    csv_data = export_df.to_csv(index=False).encode("utf-8-sig")

    st.download_button(
        label="CSV 다운로드",
        data=csv_data,
        file_name=build_export_filename(metadata),
        mime="text/csv",
        use_container_width=True,
    )


def main() -> None:
    """Run the Cloud Security Checklist app."""

    configure_page()
    initialize_check_state()
    metadata = render_sidebar()
    selected_ids = get_selected_check_ids()
    summary = build_assessment_summary(selected_ids)

    render_header(metadata)
    render_score_cards(summary)
    render_executive_note(summary)

    overview_tab, checklist_tab, risk_tab, export_tab = st.tabs(
        ["Overview", "Checklist", "Risk Register", "Export"]
    )

    with overview_tab:
        left_col, right_col = st.columns([1.05, 1])
        with left_col:
            st.subheader("카테고리별 보안 성숙도")
            render_category_cards(selected_ids)
        with right_col:
            st.subheader("카테고리 점수 요약")
            render_category_chart(selected_ids)
            render_category_table(selected_ids)
            st.subheader("심각도별 통제 현황")
            render_severity_breakdown(selected_ids)

    with checklist_tab:
        st.subheader("보안 체크리스트")
        render_checklist()
        st.subheader("Control Catalog")
        render_control_catalog()

    with risk_tab:
        st.subheader("주요 위험 요소 및 개선 권고사항")
        render_risk_register(selected_ids)

    with export_tab:
        st.subheader("점검 결과 다운로드")
        render_export_panel(metadata=metadata, selected_ids=selected_ids, summary=summary)

    render_footer()


if __name__ == "__main__":
    main()
