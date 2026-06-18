"""Streamlit interface for the Cloud Security Checklist dashboard."""

from __future__ import annotations

from datetime import date
from typing import Any

import pandas as pd
import streamlit as st

from security_checks import (
    CATEGORIES,
    SECURITY_CHECKS,
    calculate_category_scores,
    calculate_score,
    generate_recommendations,
    get_risk_level,
)


CLOUD_ENVIRONMENTS: tuple[str, ...] = ("Azure", "AWS", "GCP", "On-Premise")
CHECKBOX_PREFIX = "security_check_"

RISK_BADGE_STYLES: dict[str, dict[str, str]] = {
    "양호": {"background": "#E8F5E9", "color": "#1B5E20", "border": "#A5D6A7"},
    "주의": {"background": "#FFF8E1", "color": "#7A4F01", "border": "#FFE082"},
    "위험": {"background": "#FFF3E0", "color": "#8A3B00", "border": "#FFCC80"},
    "매우 위험": {"background": "#FFEBEE", "color": "#8B1A1A", "border": "#EF9A9A"},
}


def configure_page() -> None:
    """Configure the Streamlit page and dashboard styles."""

    st.set_page_config(
        page_title="Cloud Security Checklist",
        page_icon="C",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(
        """
        <style>
        .block-container {
            padding-top: 2rem;
            padding-bottom: 2.5rem;
        }
        .app-subtitle {
            color: #4B5563;
            font-size: 1rem;
            line-height: 1.6;
            margin-bottom: 1.5rem;
            max-width: 980px;
        }
        .score-panel {
            border: 1px solid #D1D5DB;
            border-radius: 8px;
            padding: 1rem 1.1rem;
            background: #FFFFFF;
            min-height: 128px;
        }
        .score-label {
            color: #6B7280;
            font-size: 0.82rem;
            font-weight: 600;
            margin-bottom: 0.3rem;
        }
        .score-value {
            color: #111827;
            font-size: 2.6rem;
            font-weight: 760;
            line-height: 1;
        }
        .risk-badge {
            display: inline-block;
            border-radius: 6px;
            border: 1px solid;
            padding: 0.4rem 0.65rem;
            font-weight: 700;
            margin-top: 0.45rem;
        }
        .section-note {
            color: #6B7280;
            font-size: 0.92rem;
        }
        div[data-testid="stProgress"] > div > div > div > div {
            background-color: #2563EB;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def initialize_check_state() -> None:
    """Create default checkbox session state values."""

    for check in SECURITY_CHECKS:
        st.session_state.setdefault(f"{CHECKBOX_PREFIX}{check.id}", False)


def set_all_checks(value: bool) -> None:
    """Set every checklist checkbox to the same value."""

    for check in SECURITY_CHECKS:
        st.session_state[f"{CHECKBOX_PREFIX}{check.id}"] = value


def get_selected_check_ids() -> list[str]:
    """Return the IDs of checklist items currently selected by the user."""

    return [
        check.id
        for check in SECURITY_CHECKS
        if st.session_state.get(f"{CHECKBOX_PREFIX}{check.id}", False)
    ]


def build_export_dataframe(
    *,
    organization_name: str,
    cloud_environment: str,
    checked_date: date,
    selected_ids: list[str],
    total_score: int,
    risk_level: str,
) -> pd.DataFrame:
    """Build a CSV-friendly DataFrame containing the assessment result."""

    selected = set(selected_ids)
    rows: list[dict[str, Any]] = []

    for check in SECURITY_CHECKS:
        is_checked = check.id in selected
        rows.append(
            {
                "점검일": checked_date.isoformat(),
                "회사명 또는 프로젝트명": organization_name,
                "클라우드 환경": cloud_environment,
                "카테고리": check.category,
                "점검 항목": check.title,
                "적용 여부": "Y" if is_checked else "N",
                "가중치": check.weight,
                "획득 점수": check.weight if is_checked else 0,
                "개선 권고사항": "" if is_checked else check.recommendation,
                "총 보안 점수": total_score,
                "위험 등급": risk_level,
            }
        )

    return pd.DataFrame(rows)


def render_sidebar() -> tuple[str, str, date]:
    """Render sidebar controls and return assessment metadata."""

    with st.sidebar:
        st.header("점검 정보")
        cloud_environment = st.selectbox("클라우드 환경", CLOUD_ENVIRONMENTS)
        organization_name = st.text_input(
            "회사명 또는 프로젝트명",
            placeholder="예: ABC Cloud Migration",
        ).strip()
        checked_date = date.today()
        st.caption(f"점검일: {checked_date.isoformat()}")

        st.divider()
        st.subheader("체크리스트 제어")
        select_col, reset_col = st.columns(2)
        with select_col:
            if st.button("모든 항목 선택", use_container_width=True):
                set_all_checks(True)
        with reset_col:
            if st.button("선택 초기화", use_container_width=True):
                set_all_checks(False)

    return organization_name, cloud_environment, checked_date


def render_score_summary(score: int, risk_level: str, unchecked_count: int) -> None:
    """Render the top-level score, risk level, and unchecked count."""

    style = RISK_BADGE_STYLES[risk_level]
    score_col, risk_col, issue_col = st.columns(3)

    with score_col:
        st.markdown(
            f"""
            <div class="score-panel">
                <div class="score-label">총 보안 점수</div>
                <div class="score-value">{score}<span style="font-size:1rem;color:#6B7280;"> / 100</span></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with risk_col:
        st.markdown(
            f"""
            <div class="score-panel">
                <div class="score-label">위험 등급</div>
                <div class="risk-badge" style="background:{style['background']};color:{style['color']};border-color:{style['border']};">
                    {risk_level}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with issue_col:
        st.markdown(
            f"""
            <div class="score-panel">
                <div class="score-label">주요 위험 요소</div>
                <div class="score-value">{unchecked_count}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.progress(score / 100)


def render_checklist() -> None:
    """Render checklist items grouped by security category."""

    st.subheader("보안 체크리스트")
    for category in CATEGORIES:
        with st.expander(category, expanded=True):
            for check in [item for item in SECURITY_CHECKS if item.category == category]:
                st.checkbox(
                    check.title,
                    key=f"{CHECKBOX_PREFIX}{check.id}",
                    help=f"가중치: {check.weight}점",
                )


def render_category_scores(selected_ids: list[str]) -> None:
    """Render category score progress bars and a tabular summary."""

    st.subheader("카테고리별 점수")
    category_scores = calculate_category_scores(selected_ids)

    for category, values in category_scores.items():
        label_col, value_col = st.columns([3, 1])
        with label_col:
            st.write(category)
            st.progress(values["score"] / 100)
        with value_col:
            st.metric("점수", f"{values['score']}점", f"{values['earned']}/{values['total']}")

    score_rows = [
        {
            "카테고리": category,
            "획득 점수": values["earned"],
            "총 가중치": values["total"],
            "점수": f"{values['score']}점",
        }
        for category, values in category_scores.items()
    ]
    st.dataframe(pd.DataFrame(score_rows), hide_index=True, use_container_width=True)


def render_recommendations(selected_ids: list[str]) -> None:
    """Render risks and remediation guidance for unchecked items."""

    recommendations = generate_recommendations(selected_ids)
    st.subheader("주요 위험 요소 및 개선 권고사항")

    if not recommendations:
        st.success("모든 보안 항목이 충족되었습니다. 현재 통제 수준을 유지하고 정기 점검을 계속 수행하세요.")
        return

    st.markdown(
        f"<p class='section-note'>미충족 항목 {len(recommendations)}개를 우선순위에 따라 개선하세요.</p>",
        unsafe_allow_html=True,
    )
    for recommendation in recommendations:
        with st.expander(
            f"{recommendation['category']} | {recommendation['item']} ({recommendation['weight']}점)",
            expanded=False,
        ):
            st.write(recommendation["recommendation"])


def render_download(
    *,
    organization_name: str,
    cloud_environment: str,
    checked_date: date,
    selected_ids: list[str],
    total_score: int,
    risk_level: str,
) -> None:
    """Render the CSV download button for the current assessment."""

    export_name = organization_name if organization_name else "미입력"
    export_df = build_export_dataframe(
        organization_name=export_name,
        cloud_environment=cloud_environment,
        checked_date=checked_date,
        selected_ids=selected_ids,
        total_score=total_score,
        risk_level=risk_level,
    )
    csv_data = export_df.to_csv(index=False).encode("utf-8-sig")
    file_date = checked_date.strftime("%Y%m%d")

    st.download_button(
        label="점검 결과 CSV 다운로드",
        data=csv_data,
        file_name=f"cloud_security_checklist_{file_date}.csv",
        mime="text/csv",
        use_container_width=True,
    )


def main() -> None:
    """Run the Cloud Security Checklist Streamlit app."""

    configure_page()
    initialize_check_state()
    organization_name, cloud_environment, checked_date = render_sidebar()

    st.title("Cloud Security Checklist")
    st.markdown(
        """
        <p class="app-subtitle">
        클라우드 환경의 핵심 보안 설정을 빠르게 점검하고, 점수와 위험 등급,
        카테고리별 취약 영역, 구체적인 개선 권고사항을 확인하는 보안 컨설팅 대시보드입니다.
        </p>
        """,
        unsafe_allow_html=True,
    )

    selected_ids = get_selected_check_ids()
    total_score = calculate_score(selected_ids)
    risk_level = get_risk_level(total_score)
    unchecked_count = len(SECURITY_CHECKS) - len(selected_ids)

    render_score_summary(total_score, risk_level, unchecked_count)

    st.divider()
    render_checklist()

    st.divider()
    left_col, right_col = st.columns([1, 1])
    with left_col:
        render_category_scores(selected_ids)
    with right_col:
        render_recommendations(selected_ids)

    st.divider()
    render_download(
        organization_name=organization_name,
        cloud_environment=cloud_environment,
        checked_date=checked_date,
        selected_ids=selected_ids,
        total_score=total_score,
        risk_level=risk_level,
    )


if __name__ == "__main__":
    main()
