"""Streamlit interface for the Cloud Security Checklist dashboard."""

from __future__ import annotations

from datetime import date
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
            --ink: #111827;
            --muted: #6B7280;
            --line: #D9DEE7;
            --soft: #F6F8FB;
            --panel: #FFFFFF;
            --blue: #1D4ED8;
            --teal: #0F766E;
        }
        .block-container {
            padding: 1.35rem 1.8rem 2.5rem;
            max-width: 1440px;
        }
        section[data-testid="stSidebar"] {
            background: #F8FAFC;
            border-right: 1px solid #E5E7EB;
        }
        .dashboard-title {
            color: var(--ink);
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
            margin-bottom: 1rem;
        }
        .creator-line {
            color: #374151;
            font-size: 0.88rem;
            font-weight: 650;
            margin-bottom: 0.9rem;
        }
        .creator-line strong {
            color: #111827;
        }
        .footer-notice {
            border-top: 1px solid #E5E7EB;
            color: #4B5563;
            font-size: 0.84rem;
            margin-top: 1.5rem;
            padding-top: 0.9rem;
        }
        .status-strip {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 0.7rem;
            margin: 1rem 0 1.2rem;
        }
        .strip-item,
        .metric-card,
        .insight-panel,
        .category-card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
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
            color: var(--ink);
            font-size: 0.96rem;
            font-weight: 680;
            overflow-wrap: anywhere;
        }
        .metric-card {
            min-height: 142px;
            padding: 1rem;
            border-top: 3px solid #1D4ED8;
        }
        .metric-label {
            color: var(--muted);
            font-size: 0.82rem;
            font-weight: 700;
            margin-bottom: 0.45rem;
        }
        .metric-value {
            color: var(--ink);
            font-size: 2.35rem;
            font-weight: 780;
            line-height: 1;
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
            color: var(--ink);
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
            color: var(--ink);
            font-weight: 760;
            font-size: 0.96rem;
        }
        .category-owner {
            color: var(--muted);
            font-size: 0.76rem;
            margin-top: 0.15rem;
        }
        .category-score {
            color: var(--blue);
            font-size: 1.1rem;
            font-weight: 780;
            text-align: right;
        }
        .small-muted {
            color: var(--muted);
            font-size: 0.86rem;
            line-height: 1.45;
        }
        div[data-testid="stProgress"] > div > div > div > div {
            background-color: var(--blue);
        }
        .stButton > button,
        .stDownloadButton > button {
            border-radius: 6px;
            border: 1px solid #CBD5E1;
            font-weight: 680;
        }
        div[data-testid="stDataFrame"] {
            border: 1px solid #E5E7EB;
            border-radius: 8px;
            overflow: hidden;
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
        }
        @media (max-width: 560px) {
            .status-strip {
                grid-template-columns: 1fr;
            }
            .dashboard-title {
                font-size: 1.7rem;
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


def build_export_filename(metadata: dict[str, str | date]) -> str:
    """Build a stable CSV filename from the assessment metadata."""

    checked_date = metadata["checked_date"]
    environment = str(metadata["cloud_environment"]).lower().replace("-", "_")
    scope = str(metadata["assessment_scope"]).replace("/", "_").replace(" ", "_")
    return f"cloud_security_checklist_{environment}_{scope}_{checked_date}.csv"


def render_sidebar() -> dict[str, str | date]:
    """Render assessment controls and return metadata."""

    with st.sidebar:
        st.header("Assessment Setup")
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
        st.subheader("Bulk Actions")
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

    st.markdown("<div class='dashboard-title'>Cloud Security Checklist</div>", unsafe_allow_html=True)
    st.markdown(
        f"<div class='creator-line'>Created by <strong>{CREATOR_NAME}</strong> · Copyright (c) 2026 {CREATOR_NAME}</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        """
        <div class='dashboard-subtitle'>
        클라우드 보안 통제의 적용 상태를 빠르게 점검하고, 경영진 보고에 필요한 점수,
        위험 등급, 우선 개선 항목을 한 화면에서 확인합니다.
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        f"""
        <div class='status-strip'>
            <div class='strip-item'>
                <div class='strip-label'>Organization</div>
                <div class='strip-value'>{metadata['organization_name']}</div>
            </div>
            <div class='strip-item'>
                <div class='strip-label'>Environment</div>
                <div class='strip-value'>{metadata['cloud_environment']}</div>
            </div>
            <div class='strip-item'>
                <div class='strip-label'>Scope</div>
                <div class='strip-value'>{metadata['assessment_scope']}</div>
            </div>
            <div class='strip-item'>
                <div class='strip-label'>Risk Appetite</div>
                <div class='strip-value'>{metadata['risk_appetite']}</div>
            </div>
            <div class='strip-item'>
                <div class='strip-label'>Assessment Date</div>
                <div class='strip-value'>{metadata['checked_date']}</div>
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
        Copyright (c) 2026 {CREATOR_NAME}. See the project license for usage terms.
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_score_cards(summary: dict[str, int | str]) -> None:
    """Render executive KPI cards."""

    risk_level = str(summary["risk_level"])
    risk_badge = render_badge(risk_level, RISK_STYLES[risk_level], class_name="risk-badge")
    completion = round((int(summary["checked_count"]) / int(summary["total_count"])) * 100)

    score_col, risk_col, gap_col, critical_col = st.columns(4)
    with score_col:
        st.markdown(
            f"""
            <div class='metric-card'>
                <div class='metric-label'>Security Score</div>
                <div class='metric-value'>{summary['score']}<span style='font-size:1rem;color:#6B7280;'> / 100</span></div>
                <div class='metric-help'>가중치 기반 총점</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with risk_col:
        st.markdown(
            f"""
            <div class='metric-card'>
                <div class='metric-label'>Risk Rating</div>
                {risk_badge}
                <div class='metric-help'>점수 구간 기준 자동 산정</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with gap_col:
        st.markdown(
            f"""
            <div class='metric-card'>
                <div class='metric-label'>Open Gaps</div>
                <div class='metric-value'>{summary['unchecked_count']}</div>
                <div class='metric-help'>미충족 통제 항목</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with critical_col:
        st.markdown(
            f"""
            <div class='metric-card'>
                <div class='metric-label'>Critical Gaps</div>
                <div class='metric-value'>{summary['critical_unchecked_count']}</div>
                <div class='metric-help'>우선 조치 대상</div>
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
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.progress(values["score"] / 100)


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
