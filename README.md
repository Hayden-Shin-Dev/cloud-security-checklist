# Cloud Security Checklist

Cloud Security Checklist는 클라우드 환경의 기본 보안 통제 적용 상태를 빠르게 점검하고, 보안 점수와 위험 등급, 카테고리별 성숙도, 우선 개선 항목을 확인하는 Streamlit 기반 보안 진단 대시보드입니다.

이 프로젝트는 별도 데이터베이스 없이 로컬에서 실행되며, Azure, AWS, GCP, On-Premise 환경의 사전 점검, 정기 리뷰, 보안 개선 과제 도출에 사용할 수 있습니다.

## 주요 기능

- 클라우드 환경 선택: Azure, AWS, GCP, On-Premise
- 회사명 또는 프로젝트명, 점검 담당자, 점검 범위 입력
- 15개 핵심 보안 통제 항목 점검
- 항목별 가중치 기반 100점 만점 보안 점수 계산
- 위험 등급 자동 산정: 양호, 주의, 위험, 매우 위험
- 카테고리별 보안 성숙도와 담당 영역 표시
- 미충족 항목 기반 Risk Register 제공
- 개선 권고사항과 확인 증적 힌트 제공
- 전체 선택 및 초기화 기능
- 점검 결과 CSV 다운로드

## 기술 스택

| 구분 | 기술 |
| --- | --- |
| Language | Python 3.11 이상 |
| Web UI | Streamlit |
| Data Handling | Pandas |
| Database | 사용하지 않음 |
| JavaScript Runtime | 사용하지 않음 |

## 설치 방법

```bash
git clone https://github.com/Hayden-Shin-Dev/cloud-security-checklist.git
cd cloud-security-checklist
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS 또는 Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## 실행 방법

```bash
streamlit run app.py
```

실행 후 브라우저에서 Streamlit이 안내하는 로컬 주소로 접속합니다.

```text
http://localhost:8501
http://127.0.0.1:8501
```

## 프로젝트 구조

```text
cloud-security-checklist/
├── app.py
├── security_checks.py
├── requirements.txt
├── README.md
├── .gitignore
└── sample_output/
    └── .gitkeep
```

## 파일 설명

| 파일 | 설명 |
| --- | --- |
| `app.py` | Streamlit 화면, 사용자 입력, 결과 시각화, CSV 다운로드 UI를 담당합니다. |
| `security_checks.py` | 체크리스트 데이터, 점수 계산, 위험 등급, 권고사항 생성 로직을 담당합니다. |
| `requirements.txt` | 프로젝트 실행에 필요한 Python 패키지 목록입니다. |
| `README.md` | 프로젝트 소개, 설치 및 실행, 점수 모델, 테스트 항목을 설명합니다. |
| `.gitignore` | 가상환경, 캐시, 민감 설정, 생성 파일을 Git 추적 대상에서 제외합니다. |
| `sample_output/.gitkeep` | 샘플 출력 폴더 구조를 유지합니다. |

## 보안 점수 계산 방식

각 체크리스트 항목은 중요도에 따라 가중치를 가지며, 전체 가중치 합계는 100점입니다. 사용자가 체크한 항목의 가중치를 합산하여 최종 보안 점수를 계산합니다.

```text
보안 점수 = 체크된 항목의 가중치 합계 / 전체 가중치 합계 * 100
```

현재 전체 가중치 합계는 100이므로, 체크된 항목의 가중치 합계가 최종 점수와 같습니다.

## 위험 등급 기준

| 점수 구간 | 등급 | 해석 |
| --- | --- | --- |
| 80점 이상 | 양호 | 핵심 보안 통제가 대체로 적용된 상태입니다. |
| 60점 이상 80점 미만 | 주의 | 주요 통제는 일부 적용되어 있으나 개선이 필요합니다. |
| 40점 이상 60점 미만 | 위험 | 다수의 핵심 통제가 미흡하여 우선 조치가 필요합니다. |
| 40점 미만 | 매우 위험 | 기본 보안 통제 부재 가능성이 높아 즉시 개선이 필요합니다. |

## 카테고리 구성

| 카테고리 | 주요 점검 영역 | 담당 영역 |
| --- | --- | --- |
| 계정 및 접근 관리 | MFA, 개인별 계정, 최소 권한 | Security / IAM |
| 네트워크 보안 | Default Deny, SSH/RDP 공개 제한, DB 직접 노출 방지 | Cloud Platform |
| 데이터 보호 | 저장 데이터 암호화, 전송 구간 암호화 | Data / Platform |
| 로그 및 모니터링 | 시스템/접근 로그 수집, 비정상 접근 알림 | Security Operations |
| 백업 및 운영 관리 | 정기 백업, 복구 테스트, 환경 분리, 변경 승인 | Operations |

## 테스트해야 할 항목

1. 사이드바에서 클라우드 환경과 점검 범위를 변경할 수 있는지 확인합니다.
2. 회사명, 프로젝트명, 점검 담당자가 상단 메타데이터와 CSV에 반영되는지 확인합니다.
3. 전체 선택 시 보안 점수 100점과 위험 등급 양호가 표시되는지 확인합니다.
4. 초기화 시 보안 점수 0점과 위험 등급 매우 위험이 표시되는지 확인합니다.
5. 일부 항목만 선택했을 때 카테고리별 점수가 가중치 기준으로 계산되는지 확인합니다.
6. 미충족 항목이 Risk Register에 우선순위와 함께 표시되는지 확인합니다.
7. 각 위험 요소에 개선 권고사항과 확인 증적 힌트가 표시되는지 확인합니다.
8. CSV 다운로드 파일에 점검일, 회사명, 담당자, 환경, 범위, 점수, 위험 등급이 포함되는지 확인합니다.
9. 좁은 브라우저 폭에서도 KPI 카드와 탭 레이아웃이 크게 깨지지 않는지 확인합니다.

## 운영 활용 예시

- 신규 클라우드 프로젝트 착수 전 기본 통제 사전 점검
- 월간 또는 분기별 클라우드 보안 리뷰
- 외부 컨설팅 전 내부 사전 진단
- 계정, 구독, 프로젝트별 보안 성숙도 비교
- 보안 개선 과제의 우선순위 도출

## 향후 개선 계획

- 체크리스트 항목을 YAML 또는 JSON 파일로 분리
- 클라우드 환경별 특화 통제 항목 추가
- 점검 결과 PDF 리포트 생성
- 이전 점검 결과와의 점수 비교
- 심각도와 개선 난이도 기반 우선순위 모델 고도화
- 조직별 표준 보안 통제 템플릿 지원

## 스크린샷

아래 경로에 실행 화면 이미지를 추가할 수 있습니다.

```text
sample_output/dashboard_screenshot.png
```
