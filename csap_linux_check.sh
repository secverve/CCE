#!/usr/bin/env bash
# CSAP Linux 서버 취약점 점검 스크립트 (단일 파일)
# 제작자: kosyas 안기백
# 실행 방법:
#   chmod +x csap_linux_check.sh
#   ./csap_linux_check.sh
# 주의: 본 스크립트는 read-only 진단만 수행한다.

set -u
set -o pipefail

########################################
# 2. 전역 변수
########################################
OUTPUT_DIR="./output"
DETAIL_LOG=""
SUMMARY_TSV=""

OS_ID="unknown"
OS_VERSION="unknown"
OS_FAMILY="unknown"
OS_NAME="unknown"
PKG_MANAGER="unknown"
SERVICE_MANAGER="unknown"
IS_ROOT="no"
HOST_KERNEL="unknown"
HOSTNAME_INFO="unknown"

# 항목 공통 변수
ITEM_ID=""
ITEM_NAME=""
ITEM_PURPOSE=""
ITEM_TARGET=""
ITEM_RAW=""
ITEM_RESULT="인포"
ITEM_SIGN="INFO"
ITEM_REASON=""
ITEM_ACTION=""
ITEM_EVIDENCE=""

########################################
# 3. 공통 함수
########################################
have_cmd() { command -v "$1" >/dev/null 2>&1; }

set_item_meta() {
  ITEM_ID="$1"; ITEM_NAME="$2"; ITEM_PURPOSE="$3"; ITEM_TARGET="$4"
  ITEM_RAW=""; ITEM_RESULT="인포"; ITEM_SIGN="INFO"; ITEM_REASON=""; ITEM_ACTION=""; ITEM_EVIDENCE=""
}

set_good() {
  ITEM_RESULT="양호"; ITEM_SIGN="Y"; ITEM_REASON="$1"; ITEM_ACTION="$2"; ITEM_EVIDENCE="$3"
}

set_weak() {
  ITEM_RESULT="취약"; ITEM_SIGN="N"; ITEM_REASON="$1"; ITEM_ACTION="$2"; ITEM_EVIDENCE="$3"
}

set_info() {
  ITEM_RESULT="인포"; ITEM_SIGN="INFO"; ITEM_REASON="$1"; ITEM_ACTION="$2"; ITEM_EVIDENCE="$3"
}

first_existing_file() {
  for f in "$@"; do
    [ -f "$f" ] && { printf '%s' "$f"; return 0; }
  done
  return 1
}

########################################
# 4. OS 탐지 함수
########################################
detect_os() {
  HOST_KERNEL="$(uname -srmo 2>/dev/null || uname -a 2>/dev/null || echo unknown)"
  HOSTNAME_INFO="$(hostnamectl 2>/dev/null | head -n 5 || uname -n 2>/dev/null || echo unknown)"

  if [ "$(id -u)" -eq 0 ]; then IS_ROOT="yes"; else IS_ROOT="no"; fi

  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_NAME="${PRETTY_NAME:-${NAME:-unknown}}"
    case "${ID:-}" in
      rocky|rhel|centos|almalinux|ol|fedora) OS_FAMILY="rhel" ;;
      ubuntu|debian) OS_FAMILY="debian" ;;
      alpine) OS_FAMILY="alpine" ;;
      *)
        case "${ID_LIKE:-}" in
          *rhel*|*centos*|*fedora*) OS_FAMILY="rhel" ;;
          *debian*|*ubuntu*) OS_FAMILY="debian" ;;
          *alpine*) OS_FAMILY="alpine" ;;
          *) OS_FAMILY="unknown" ;;
        esac
        ;;
    esac
  fi

  if have_cmd rpm; then PKG_MANAGER="rpm"; elif have_cmd dpkg; then PKG_MANAGER="dpkg"; elif have_cmd apk; then PKG_MANAGER="apk"; fi
  if have_cmd systemctl; then SERVICE_MANAGER="systemd"; elif have_cmd service; then SERVICE_MANAGER="service"; elif have_cmd rc-service; then SERVICE_MANAGER="openrc"; fi
}

########################################
# 5. 출력 초기화 함수
########################################
init_output() {
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$OUTPUT_DIR"
  DETAIL_LOG="$OUTPUT_DIR/result_detail_${ts}.txt"
  SUMMARY_TSV="$OUTPUT_DIR/result_summary_${ts}.tsv"

  {
    echo "[CSAP Linux 점검 상세 로그]"
    echo "실행시각: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo
    echo "[시스템 정보]"
    echo "배포판: $OS_NAME"
    echo "버전: $OS_VERSION"
    echo "계열: $OS_FAMILY"
    if [ "$IS_ROOT" = "yes" ]; then echo "권한: root"; else echo "권한: non-root"; fi
    echo "패키지 관리자: $PKG_MANAGER"
    echo "서비스 관리자: $SERVICE_MANAGER"
    echo "커널: $HOST_KERNEL"
    echo "호스트 정보:"
    echo "$HOSTNAME_INFO"
    echo
  } > "$DETAIL_LOG"

  printf '항목ID\t항목명\t진단결과\t판정기호\t판정사유\t기입문구\t핵심근거로그\n' > "$SUMMARY_TSV"
}

########################################
# 7. 결과 기록 함수
########################################
record_result() {
  {
    echo "============================================================"
    echo "항목 ID: $ITEM_ID"
    echo "항목명: $ITEM_NAME"
    echo "점검 목적: $ITEM_PURPOSE"
    echo "사용 명령어/확인 파일: $ITEM_TARGET"
    echo "[실제 수집 결과 원문]"
    echo "$ITEM_RAW"
    echo "진단 결과: $ITEM_RESULT"
    echo "판정 사유: $ITEM_REASON"
    echo "기입문구: $ITEM_ACTION"
    echo "핵심근거로그: $ITEM_EVIDENCE"
    echo
  } >> "$DETAIL_LOG"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$ITEM_ID" "$ITEM_NAME" "$ITEM_RESULT" "$ITEM_SIGN" \
    "$(printf '%s' "$ITEM_REASON" | tr '\t\n' '  ')" \
    "$(printf '%s' "$ITEM_ACTION" | tr '\t\n' '  ')" \
    "$(printf '%s' "$ITEM_EVIDENCE" | tr '\t\n' '  ')" >> "$SUMMARY_TSV"
}

########################################
# 8. 항목별 점검 함수 check_l01 ~ check_l36
########################################
# L-01 /etc/passwd 파일 권한
check_l01() {
  set_item_meta "L-01" "passwd 파일 권한" "계정정보 파일 권한 보호 여부 확인" "stat -c '%a %U %G %n' /etc/passwd"
  if [ ! -e /etc/passwd ]; then ITEM_RAW="/etc/passwd 파일 없음"; set_info "/etc/passwd 파일이 확인되지 않아 추가 확인 필요하므로 인포." "/etc/passwd 파일이 확인되지 않아 추가 확인 필요하므로 인포." "파일 없음"; return; fi
  ITEM_RAW="$(stat -c '%a %U %G %n' /etc/passwd 2>/dev/null || echo '확인 실패')"
  if echo "$ITEM_RAW" | grep -Eq '^[0-9]+'; then
    local mode owner group
    mode="$(echo "$ITEM_RAW" | awk '{print $1}')"; owner="$(echo "$ITEM_RAW" | awk '{print $2}')"; group="$(echo "$ITEM_RAW" | awk '{print $3}')"
    if [ "$owner" = "root" ] && [ "$group" = "root" ] && [ "$mode" -le 644 ]; then
      set_good "/etc/passwd 소유자와 권한이 기준을 충족하므로 양호." "/etc/passwd 소유자와 권한이 기준을 충족하므로 양호." "$ITEM_RAW"
    else
      set_weak "/etc/passwd 소유자 또는 권한이 기준을 충족하지 않으므로 취약." "/etc/passwd 소유자 또는 권한이 기준을 충족하지 않으므로 취약." "$ITEM_RAW"
    fi
  else
    set_info "/etc/passwd 권한 정보가 확인되지 않아 추가 확인 필요하므로 인포." "/etc/passwd 권한 정보가 확인되지 않아 추가 확인 필요하므로 인포." "$ITEM_RAW"
  fi
}

# L-02 /etc/shadow 파일 권한
check_l02() {
  set_item_meta "L-02" "shadow 파일 권한" "인증정보 파일 권한 보호 여부 확인" "stat -c '%a %U %G %n' /etc/shadow"
  if [ ! -e /etc/shadow ]; then ITEM_RAW="/etc/shadow 파일 없음"; set_info "/etc/shadow 파일이 확인되지 않아 추가 확인 필요하므로 인포." "/etc/shadow 파일이 확인되지 않아 추가 확인 필요하므로 인포." "파일 없음"; return; fi
  ITEM_RAW="$(stat -c '%a %U %G %n' /etc/shadow 2>/dev/null || echo '확인 실패')"
  if echo "$ITEM_RAW" | grep -Eq '^[0-9]+'; then
    local mode owner group
    mode="$(echo "$ITEM_RAW" | awk '{print $1}')"; owner="$(echo "$ITEM_RAW" | awk '{print $2}')"; group="$(echo "$ITEM_RAW" | awk '{print $3}')"
    if [ "$owner" = "root" ] && { [ "$group" = "root" ] || [ "$group" = "shadow" ]; } && [ "$mode" -le 640 ]; then
      set_good "/etc/shadow 소유자와 권한이 기준을 충족하므로 양호." "/etc/shadow 소유자와 권한이 기준을 충족하므로 양호." "$ITEM_RAW"
    else
      set_weak "/etc/shadow 소유자 또는 권한이 기준을 충족하지 않으므로 취약." "/etc/shadow 소유자 또는 권한이 기준을 충족하지 않으므로 취약." "$ITEM_RAW"
    fi
  else
    set_info "/etc/shadow 권한 정보가 확인되지 않아 추가 확인 필요하므로 인포." "/etc/shadow 권한 정보가 확인되지 않아 추가 확인 필요하므로 인포." "$ITEM_RAW"
  fi
}

# L-03 /etc/group 파일 권한
check_l03() {
  set_item_meta "L-03" "group 파일 권한" "그룹정보 파일 권한 보호 여부 확인" "stat -c '%a %U %G %n' /etc/group"
  [ -e /etc/group ] || { ITEM_RAW="/etc/group 파일 없음"; set_info "/etc/group 파일이 확인되지 않아 추가 확인 필요하므로 인포." "/etc/group 파일이 확인되지 않아 추가 확인 필요하므로 인포." "파일 없음"; return; }
  ITEM_RAW="$(stat -c '%a %U %G %n' /etc/group 2>/dev/null || echo '확인 실패')"
  local mode owner group
  mode="$(echo "$ITEM_RAW" | awk '{print $1}')"; owner="$(echo "$ITEM_RAW" | awk '{print $2}')"; group="$(echo "$ITEM_RAW" | awk '{print $3}')"
  if echo "$mode" | grep -Eq '^[0-9]+$' && [ "$owner" = "root" ] && [ "$group" = "root" ] && [ "$mode" -le 644 ]; then
    set_good "/etc/group 소유자와 권한이 기준을 충족하므로 양호." "/etc/group 소유자와 권한이 기준을 충족하므로 양호." "$ITEM_RAW"
  elif echo "$mode" | grep -Eq '^[0-9]+$'; then
    set_weak "/etc/group 소유자 또는 권한이 기준을 충족하지 않으므로 취약." "/etc/group 소유자 또는 권한이 기준을 충족하지 않으므로 취약." "$ITEM_RAW"
  else
    set_info "/etc/group 권한 정보가 확인되지 않아 추가 확인 필요하므로 인포." "/etc/group 권한 정보가 확인되지 않아 추가 확인 필요하므로 인포." "$ITEM_RAW"
  fi
}

# L-04 /etc/gshadow 파일 권한
check_l04() {
  set_item_meta "L-04" "gshadow 파일 권한" "민감 그룹정보 파일 권한 보호 여부 확인" "stat -c '%a %U %G %n' /etc/gshadow"
  [ -e /etc/gshadow ] || { ITEM_RAW="/etc/gshadow 파일 없음"; set_info "/etc/gshadow 파일이 확인되지 않아 추가 확인 필요하므로 인포." "/etc/gshadow 파일이 확인되지 않아 추가 확인 필요하므로 인포." "파일 없음"; return; }
  ITEM_RAW="$(stat -c '%a %U %G %n' /etc/gshadow 2>/dev/null || echo '확인 실패')"
  local mode owner group
  mode="$(echo "$ITEM_RAW" | awk '{print $1}')"; owner="$(echo "$ITEM_RAW" | awk '{print $2}')"; group="$(echo "$ITEM_RAW" | awk '{print $3}')"
  if echo "$mode" | grep -Eq '^[0-9]+$' && [ "$owner" = "root" ] && { [ "$group" = "root" ] || [ "$group" = "shadow" ]; } && [ "$mode" -le 640 ]; then
    set_good "/etc/gshadow 소유자와 권한이 기준을 충족하므로 양호." "/etc/gshadow 소유자와 권한이 기준을 충족하므로 양호." "$ITEM_RAW"
  elif echo "$mode" | grep -Eq '^[0-9]+$'; then
    set_weak "/etc/gshadow 소유자 또는 권한이 기준을 충족하지 않으므로 취약." "/etc/gshadow 소유자 또는 권한이 기준을 충족하지 않으므로 취약." "$ITEM_RAW"
  else
    set_info "/etc/gshadow 권한 정보가 확인되지 않아 추가 확인 필요하므로 인포." "/etc/gshadow 권한 정보가 확인되지 않아 추가 확인 필요하므로 인포." "$ITEM_RAW"
  fi
}

# L-05 root UID 확인
check_l05() {
  set_item_meta "L-05" "root UID 확인" "root 계정 UID 무결성 확인" "grep '^root:' /etc/passwd"
  ITEM_RAW="$(grep '^root:' /etc/passwd 2>/dev/null || echo '확인 실패')"
  if [ -z "$ITEM_RAW" ] || [ "$ITEM_RAW" = "확인 실패" ]; then
    set_info "root 계정 정보가 확인되지 않아 추가 확인 필요하므로 인포." "root 계정 정보가 확인되지 않아 추가 확인 필요하므로 인포." "$ITEM_RAW"
  elif echo "$ITEM_RAW" | awk -F: '{exit !($3==0)}'; then
    set_good "root 계정 UID가 0으로 설정되어 있으므로 양호." "root 계정 UID가 0으로 설정되어 있으므로 양호." "$ITEM_RAW"
  else
    set_weak "root 계정 UID가 0이 아니므로 취약." "root 계정 UID가 0이 아니므로 취약." "$ITEM_RAW"
  fi
}

# L-06 UID 0 계정 단일성
check_l06() {
  set_item_meta "L-06" "UID 0 계정 단일성" "불필요한 관리자 계정 존재 여부 확인" 'awk -F: '\''($3==0){print $1}'\'' /etc/passwd'
  ITEM_RAW="$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null || echo '확인 실패')"
  local cnt
  cnt="$(printf '%s\n' "$ITEM_RAW" | grep -cv '^$')"
  if [ "$ITEM_RAW" = "확인 실패" ]; then
    set_info "UID 0 계정 정보가 확인되지 않아 추가 확인 필요하므로 인포." "UID 0 계정 정보가 확인되지 않아 추가 확인 필요하므로 인포." "$ITEM_RAW"
  elif [ "$cnt" -eq 1 ] && [ "$ITEM_RAW" = "root" ]; then
    set_good "UID 0 계정이 root 단일 계정이므로 양호." "UID 0 계정이 root 단일 계정이므로 양호." "$ITEM_RAW"
  else
    set_weak "UID 0 계정이 root 단일 계정이 아니므로 취약." "UID 0 계정이 root 단일 계정이 아니므로 취약." "$(printf '%s' "$ITEM_RAW" | head -n 3)"
  fi
}

# L-07 패스워드 빈 값 계정
check_l07() {
  set_item_meta "L-07" "빈 패스워드 계정" "빈 패스워드 계정 존재 여부 확인" 'awk -F: '\''($2==""){print $1}'\'' /etc/shadow'
  if [ "$IS_ROOT" != "yes" ] && [ ! -r /etc/shadow ]; then
    ITEM_RAW="/etc/shadow 접근 권한 없음"
    set_info "패스워드 정보가 확인되지 않아 추가 확인 필요하므로 인포." "패스워드 정보가 확인되지 않아 추가 확인 필요하므로 인포." "$ITEM_RAW"
    return
  fi
  ITEM_RAW="$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)"
  if [ -z "$ITEM_RAW" ]; then
    set_good "빈 패스워드 계정이 확인되지 않으므로 양호." "빈 패스워드 계정이 확인되지 않으므로 양호." "빈 패스워드 계정 없음"
  else
    set_weak "빈 패스워드 계정이 확인되므로 취약." "빈 패스워드 계정이 확인되므로 취약." "$(printf '%s' "$ITEM_RAW" | head -n 3)"
  fi
}

# L-08 PASS_MAX_DAYS
check_l08() {
  set_item_meta "L-08" "패스워드 최대 사용일" "장기 미변경 패스워드 제한 확인" "grep '^PASS_MAX_DAYS' /etc/login.defs"
  local line val
  line="$(grep -E '^PASS_MAX_DAYS[[:space:]]+' /etc/login.defs 2>/dev/null | head -n 1)"
  ITEM_RAW="$line"
  val="$(echo "$line" | awk '{print $2}')"
  if [ -z "$line" ]; then
    set_info "PASS_MAX_DAYS 설정이 확인되지 않아 추가 확인 필요하므로 인포." "PASS_MAX_DAYS 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음"
  elif echo "$val" | grep -Eq '^[0-9]+$' && [ "$val" -le 90 ]; then
    set_good "PASS_MAX_DAYS가 90 이하로 설정되어 있으므로 양호." "PASS_MAX_DAYS가 90 이하로 설정되어 있으므로 양호." "$line"
  elif echo "$val" | grep -Eq '^[0-9]+$'; then
    set_weak "PASS_MAX_DAYS가 90 초과로 설정되어 있으므로 취약." "PASS_MAX_DAYS가 90 초과로 설정되어 있으므로 취약." "$line"
  else
    set_info "PASS_MAX_DAYS 값이 확인되지 않아 추가 확인 필요하므로 인포." "PASS_MAX_DAYS 값이 확인되지 않아 추가 확인 필요하므로 인포." "$line"
  fi
}

# L-09 PASS_MIN_DAYS
check_l09() {
  set_item_meta "L-09" "패스워드 최소 사용일" "즉시 재변경 우회 방지 설정 확인" "grep '^PASS_MIN_DAYS' /etc/login.defs"
  local line val
  line="$(grep -E '^PASS_MIN_DAYS[[:space:]]+' /etc/login.defs 2>/dev/null | head -n 1)"; ITEM_RAW="$line"; val="$(echo "$line" | awk '{print $2}')"
  if [ -z "$line" ]; then
    set_info "PASS_MIN_DAYS 설정이 확인되지 않아 추가 확인 필요하므로 인포." "PASS_MIN_DAYS 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음"
  elif echo "$val" | grep -Eq '^[0-9]+$' && [ "$val" -ge 1 ]; then
    set_good "PASS_MIN_DAYS가 1 이상으로 설정되어 있으므로 양호." "PASS_MIN_DAYS가 1 이상으로 설정되어 있으므로 양호." "$line"
  elif echo "$val" | grep -Eq '^[0-9]+$'; then
    set_weak "PASS_MIN_DAYS가 0으로 설정되어 있으므로 취약." "PASS_MIN_DAYS가 0으로 설정되어 있으므로 취약." "$line"
  else
    set_info "PASS_MIN_DAYS 값이 확인되지 않아 추가 확인 필요하므로 인포." "PASS_MIN_DAYS 값이 확인되지 않아 추가 확인 필요하므로 인포." "$line"
  fi
}

# L-10 PASS_WARN_AGE
check_l10() {
  set_item_meta "L-10" "패스워드 만료 경고일" "만료 전 경고일수 설정 확인" "grep '^PASS_WARN_AGE' /etc/login.defs"
  local line val
  line="$(grep -E '^PASS_WARN_AGE[[:space:]]+' /etc/login.defs 2>/dev/null | head -n 1)"; ITEM_RAW="$line"; val="$(echo "$line" | awk '{print $2}')"
  if [ -z "$line" ]; then
    set_info "PASS_WARN_AGE 설정이 확인되지 않아 추가 확인 필요하므로 인포." "PASS_WARN_AGE 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음"
  elif echo "$val" | grep -Eq '^[0-9]+$' && [ "$val" -ge 7 ]; then
    set_good "PASS_WARN_AGE가 7 이상으로 설정되어 있으므로 양호." "PASS_WARN_AGE가 7 이상으로 설정되어 있으므로 양호." "$line"
  elif echo "$val" | grep -Eq '^[0-9]+$'; then
    set_weak "PASS_WARN_AGE가 7 미만으로 설정되어 있으므로 취약." "PASS_WARN_AGE가 7 미만으로 설정되어 있으므로 취약." "$line"
  else
    set_info "PASS_WARN_AGE 값이 확인되지 않아 추가 확인 필요하므로 인포." "PASS_WARN_AGE 값이 확인되지 않아 추가 확인 필요하므로 인포." "$line"
  fi
}

# L-11 시스템 계정 쉘 제한
check_l11() {
  set_item_meta "L-11" "시스템 계정 쉘 제한" "시스템 계정 로그인 쉘 제한 여부 확인" 'awk -F: '\''($3<1000 && $1!="root" && $7!~/nologin|false/){print $1":"$7}'\'' /etc/passwd'
  ITEM_RAW="$(awk -F: '($3<1000 && $1!="root" && $7!~/nologin|false/){print $1":"$7}' /etc/passwd 2>/dev/null)"
  if [ -z "$ITEM_RAW" ]; then
    set_good "시스템 계정 로그인 쉘이 제한되어 있으므로 양호." "시스템 계정 로그인 쉘이 제한되어 있으므로 양호." "제한 위반 계정 없음"
  else
    set_weak "시스템 계정 로그인 쉘 제한이 확인되지 않으므로 취약." "시스템 계정 로그인 쉘 제한이 확인되지 않으므로 취약." "$(printf '%s' "$ITEM_RAW" | head -n 3)"
  fi
}

# L-12 중복 사용자명
check_l12() {
  set_item_meta "L-12" "중복 사용자명" "사용자명 중복 여부 확인" "cut -d: -f1 /etc/passwd | sort | uniq -d"
  ITEM_RAW="$(cut -d: -f1 /etc/passwd 2>/dev/null | sort | uniq -d)"
  if [ -z "$ITEM_RAW" ]; then set_good "중복 사용자명이 확인되지 않으므로 양호." "중복 사용자명이 확인되지 않으므로 양호." "중복 사용자명 없음"; else set_weak "중복 사용자명이 확인되므로 취약." "중복 사용자명이 확인되므로 취약." "$(printf '%s' "$ITEM_RAW" | head -n 3)"; fi
}

# L-13 중복 UID
check_l13() {
  set_item_meta "L-13" "중복 UID" "UID 중복 여부 확인" "cut -d: -f3 /etc/passwd | sort | uniq -d"
  ITEM_RAW="$(cut -d: -f3 /etc/passwd 2>/dev/null | sort | uniq -d)"
  if [ -z "$ITEM_RAW" ]; then set_good "중복 UID가 확인되지 않으므로 양호." "중복 UID가 확인되지 않으므로 양호." "중복 UID 없음"; else set_weak "중복 UID가 확인되므로 취약." "중복 UID가 확인되므로 취약." "$(printf '%s' "$ITEM_RAW" | head -n 3)"; fi
}

# L-14 중복 GID
check_l14() {
  set_item_meta "L-14" "중복 GID" "GID 중복 여부 확인" "cut -d: -f3 /etc/group | sort | uniq -d"
  ITEM_RAW="$(cut -d: -f3 /etc/group 2>/dev/null | sort | uniq -d)"
  if [ -z "$ITEM_RAW" ]; then set_good "중복 GID가 확인되지 않으므로 양호." "중복 GID가 확인되지 않으므로 양호." "중복 GID 없음"; else set_weak "중복 GID가 확인되므로 취약." "중복 GID가 확인되므로 취약." "$(printf '%s' "$ITEM_RAW" | head -n 3)"; fi
}

# L-15 중복 그룹명
check_l15() {
  set_item_meta "L-15" "중복 그룹명" "그룹명 중복 여부 확인" "cut -d: -f1 /etc/group | sort | uniq -d"
  ITEM_RAW="$(cut -d: -f1 /etc/group 2>/dev/null | sort | uniq -d)"
  if [ -z "$ITEM_RAW" ]; then set_good "중복 그룹명이 확인되지 않으므로 양호." "중복 그룹명이 확인되지 않으므로 양호." "중복 그룹명 없음"; else set_weak "중복 그룹명이 확인되므로 취약." "중복 그룹명이 확인되므로 취약." "$(printf '%s' "$ITEM_RAW" | head -n 3)"; fi
}

# L-16 /etc 내 world writable 파일
check_l16() {
  set_item_meta "L-16" "world writable 파일" "중요 경로 내 과도한 쓰기권한 파일 확인" "find /etc -xdev -type f -perm -0002"
  ITEM_RAW="$(find /etc -xdev -type f -perm -0002 2>/dev/null | head -n 20)"
  if [ -z "$ITEM_RAW" ]; then set_good "/etc 경로에서 world writable 파일이 확인되지 않으므로 양호." "/etc 경로에서 world writable 파일이 확인되지 않으므로 양호." "해당 파일 없음"; else set_weak "/etc 경로에서 world writable 파일이 확인되므로 취약." "/etc 경로에서 world writable 파일이 확인되므로 취약." "$(printf '%s' "$ITEM_RAW" | head -n 3)"; fi
}

# L-17 su 명령 권한
check_l17() {
  set_item_meta "L-17" "su 명령 권한" "su 명령 파일 권한 과다 여부 확인" "stat -c '%a %U %G %n' /bin/su /usr/bin/su"
  local su_path
  su_path="$(first_existing_file /bin/su /usr/bin/su 2>/dev/null || true)"
  if [ -z "$su_path" ]; then ITEM_RAW="su 명령 파일 없음"; set_info "su 명령 파일이 확인되지 않아 추가 확인 필요하므로 인포." "su 명령 파일이 확인되지 않아 추가 확인 필요하므로 인포." "파일 없음"; return; fi
  ITEM_RAW="$(stat -c '%a %U %G %n' "$su_path" 2>/dev/null || echo '확인 실패')"
  local mode; mode="$(echo "$ITEM_RAW" | awk '{print $1}')"
  if echo "$mode" | grep -Eq '^[0-9]+$' && [ "$mode" -le 4750 ]; then
    set_good "su 명령 권한이 기준 이하이므로 양호." "su 명령 권한이 기준 이하이므로 양호." "$ITEM_RAW"
  elif echo "$mode" | grep -Eq '^[0-9]+$'; then
    set_weak "su 명령 권한이 기준 초과이므로 취약." "su 명령 권한이 기준 초과이므로 취약." "$ITEM_RAW"
  else
    set_info "su 명령 권한이 확인되지 않아 추가 확인 필요하므로 인포." "su 명령 권한이 확인되지 않아 추가 확인 필요하므로 인포." "$ITEM_RAW"
  fi
}

# L-18 SSH PermitRootLogin
check_l18() {
  set_item_meta "L-18" "SSH root 원격접속 제한" "root 직접 원격접속 제한 여부 확인" "grep -E '^PermitRootLogin' /etc/ssh/sshd_config"
  local file line
  file="$(first_existing_file /etc/ssh/sshd_config)"
  [ -n "$file" ] || { ITEM_RAW="sshd_config 파일 없음"; set_info "SSH 설정 파일이 확인되지 않아 추가 확인 필요하므로 인포." "SSH 설정 파일이 확인되지 않아 추가 확인 필요하므로 인포." "파일 없음"; return; }
  line="$(grep -Ehi '^[[:space:]]*PermitRootLogin[[:space:]]+' "$file" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -n 1)"
  ITEM_RAW="$line"
  if [ -z "$line" ]; then set_info "PermitRootLogin 설정이 확인되지 않아 추가 확인 필요하므로 인포." "PermitRootLogin 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음";
  elif echo "$line" | grep -Eiq 'PermitRootLogin[[:space:]]+no([[:space:]]|$)'; then set_good "PermitRootLogin이 no로 설정되어 있으므로 양호." "PermitRootLogin이 no로 설정되어 있으므로 양호." "$line";
  else set_weak "PermitRootLogin이 no가 아니므로 취약." "PermitRootLogin이 no가 아니므로 취약." "$line"; fi
}

# L-19 SSH PasswordAuthentication
check_l19() {
  set_item_meta "L-19" "SSH 패스워드 인증 제한" "패스워드 기반 SSH 인증 제한 여부 확인" "grep -E '^PasswordAuthentication' /etc/ssh/sshd_config"
  local line
  line="$(grep -Ehi '^[[:space:]]*PasswordAuthentication[[:space:]]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -n 1)"
  ITEM_RAW="$line"
  if [ -z "$line" ]; then set_info "PasswordAuthentication 설정이 확인되지 않아 추가 확인 필요하므로 인포." "PasswordAuthentication 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음";
  elif echo "$line" | grep -Eiq 'PasswordAuthentication[[:space:]]+no([[:space:]]|$)'; then set_good "PasswordAuthentication이 no로 설정되어 있으므로 양호." "PasswordAuthentication이 no로 설정되어 있으므로 양호." "$line";
  else set_weak "PasswordAuthentication이 no가 아니므로 취약." "PasswordAuthentication이 no가 아니므로 취약." "$line"; fi
}

# L-20 SSH Protocol 설정
check_l20() {
  set_item_meta "L-20" "SSH Protocol 설정" "취약한 프로토콜 사용 여부 확인" "grep -E '^Protocol' /etc/ssh/sshd_config"
  ITEM_RAW="$(grep -Ehi '^[[:space:]]*Protocol[[:space:]]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -n 1)"
  if [ -z "$ITEM_RAW" ]; then
    set_info "SSH Protocol 설정이 확인되지 않아 추가 확인 필요하므로 인포." "SSH Protocol 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음"
  elif echo "$ITEM_RAW" | grep -Eiq 'Protocol[[:space:]]+2([[:space:]]|$)'; then
    set_good "SSH Protocol이 2로 설정되어 있으므로 양호." "SSH Protocol이 2로 설정되어 있으므로 양호." "$ITEM_RAW"
  else
    set_weak "SSH Protocol이 2가 아니므로 취약." "SSH Protocol이 2가 아니므로 취약." "$ITEM_RAW"
  fi
}

# L-21 기본 umask
check_l21() {
  set_item_meta "L-21" "기본 umask 설정" "사용자 기본 권한 제한 여부 확인" "grep -E 'umask' /etc/profile /etc/bashrc /etc/login.defs"
  ITEM_RAW="$(grep -Ehi '^[[:space:]]*umask[[:space:]]+' /etc/profile /etc/bashrc /etc/login.defs 2>/dev/null | head -n 20)"
  if [ -z "$ITEM_RAW" ]; then set_info "umask 설정이 확인되지 않아 추가 확인 필요하므로 인포." "umask 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음"; return; fi
  if echo "$ITEM_RAW" | grep -Eq 'umask[[:space:]]+0?2[27]'; then
    set_good "umask가 022 또는 027로 설정되어 있으므로 양호." "umask가 022 또는 027로 설정되어 있으므로 양호." "$(echo "$ITEM_RAW" | head -n 3)"
  else
    set_weak "umask가 권장값으로 설정되지 않았으므로 취약." "umask가 권장값으로 설정되지 않았으므로 취약." "$(echo "$ITEM_RAW" | head -n 3)"
  fi
}

# L-22 cron 접근제어 파일 권한
check_l22() {
  set_item_meta "L-22" "cron 접근제어" "cron 허용/차단 파일 권한 확인" "stat -c '%a %U %G %n' /etc/cron.allow /etc/cron.deny"
  ITEM_RAW="$(stat -c '%a %U %G %n' /etc/cron.allow /etc/cron.deny 2>/dev/null | head -n 5)"
  if [ -z "$ITEM_RAW" ]; then set_info "cron 접근제어 파일이 확인되지 않아 추가 확인 필요하므로 인포." "cron 접근제어 파일이 확인되지 않아 추가 확인 필요하므로 인포." "파일 없음"; return; fi
  if echo "$ITEM_RAW" | awk '{if($1>640 || $2!="root") bad=1} END{exit bad}'; then
    set_good "cron 접근제어 파일 권한이 기준을 충족하므로 양호." "cron 접근제어 파일 권한이 기준을 충족하므로 양호." "$(echo "$ITEM_RAW" | head -n 3)"
  else
    set_weak "cron 접근제어 파일 권한이 기준을 충족하지 않으므로 취약." "cron 접근제어 파일 권한이 기준을 충족하지 않으므로 취약." "$(echo "$ITEM_RAW" | head -n 3)"
  fi
}

# L-23 at 접근제어 파일 권한
check_l23() {
  set_item_meta "L-23" "at 접근제어" "at 허용/차단 파일 권한 확인" "stat -c '%a %U %G %n' /etc/at.allow /etc/at.deny"
  ITEM_RAW="$(stat -c '%a %U %G %n' /etc/at.allow /etc/at.deny 2>/dev/null | head -n 5)"
  if [ -z "$ITEM_RAW" ]; then set_info "at 접근제어 파일이 확인되지 않아 추가 확인 필요하므로 인포." "at 접근제어 파일이 확인되지 않아 추가 확인 필요하므로 인포." "파일 없음"; return; fi
  if echo "$ITEM_RAW" | awk '{if($1>640 || $2!="root") bad=1} END{exit bad}'; then
    set_good "at 접근제어 파일 권한이 기준을 충족하므로 양호." "at 접근제어 파일 권한이 기준을 충족하므로 양호." "$(echo "$ITEM_RAW" | head -n 3)"
  else
    set_weak "at 접근제어 파일 권한이 기준을 충족하지 않으므로 취약." "at 접근제어 파일 권한이 기준을 충족하지 않으므로 취약." "$(echo "$ITEM_RAW" | head -n 3)"
  fi
}

# L-24 PASS_MIN_LEN
check_l24() {
  set_item_meta "L-24" "패스워드 최소 길이" "패스워드 길이 정책 확인" "grep -E '^PASS_MIN_LEN' /etc/login.defs"
  local line val
  line="$(grep -E '^PASS_MIN_LEN[[:space:]]+' /etc/login.defs 2>/dev/null | head -n 1)"; ITEM_RAW="$line"; val="$(echo "$line" | awk '{print $2}')"
  if [ -z "$line" ]; then set_info "PASS_MIN_LEN 설정이 확인되지 않아 추가 확인 필요하므로 인포." "PASS_MIN_LEN 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음";
  elif echo "$val" | grep -Eq '^[0-9]+$' && [ "$val" -ge 8 ]; then set_good "PASS_MIN_LEN이 8 이상으로 설정되어 있으므로 양호." "PASS_MIN_LEN이 8 이상으로 설정되어 있으므로 양호." "$line";
  elif echo "$val" | grep -Eq '^[0-9]+$'; then set_weak "PASS_MIN_LEN이 8 미만으로 설정되어 있으므로 취약." "PASS_MIN_LEN이 8 미만으로 설정되어 있으므로 취약." "$line";
  else set_info "PASS_MIN_LEN 값이 확인되지 않아 추가 확인 필요하므로 인포." "PASS_MIN_LEN 값이 확인되지 않아 추가 확인 필요하므로 인포." "$line"; fi
}

# L-25 세션 타임아웃(TMOUT)
check_l25() {
  set_item_meta "L-25" "세션 타임아웃" "유휴 세션 자동 종료 설정 확인" "grep -E 'TMOUT' /etc/profile /etc/bashrc"
  ITEM_RAW="$(grep -Ehi '^[[:space:]]*TMOUT=' /etc/profile /etc/bashrc /etc/profile.d/*.sh 2>/dev/null | head -n 10)"
  local tm
  tm="$(echo "$ITEM_RAW" | tail -n 1 | cut -d= -f2 | tr -cd '0-9')"
  if [ -z "$ITEM_RAW" ]; then set_info "TMOUT 설정이 확인되지 않아 추가 확인 필요하므로 인포." "TMOUT 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음";
  elif echo "$tm" | grep -Eq '^[0-9]+$' && [ "$tm" -le 900 ] && [ "$tm" -gt 0 ]; then set_good "TMOUT이 900 이하로 설정되어 있으므로 양호." "TMOUT이 900 이하로 설정되어 있으므로 양호." "$(echo "$ITEM_RAW" | tail -n 1)";
  elif echo "$tm" | grep -Eq '^[0-9]+$'; then set_weak "TMOUT이 900 초과이거나 0이므로 취약." "TMOUT이 900 초과이거나 0이므로 취약." "$(echo "$ITEM_RAW" | tail -n 1)";
  else set_info "TMOUT 값이 확인되지 않아 추가 확인 필요하므로 인포." "TMOUT 값이 확인되지 않아 추가 확인 필요하므로 인포." "$ITEM_RAW"; fi
}

# L-26 core dump 제한
check_l26() {
  set_item_meta "L-26" "core dump 제한" "core dump 비활성화 설정 확인" "grep -E 'core' /etc/security/limits.conf /etc/systemd/coredump.conf"
  ITEM_RAW="$(grep -Ehi '(^\*\s+hard\s+core\s+0|Storage=none|ProcessSizeMax=0)' /etc/security/limits.conf /etc/security/limits.d/*.conf /etc/systemd/coredump.conf 2>/dev/null | head -n 10)"
  if [ -z "$ITEM_RAW" ]; then
    set_info "core dump 제한 설정이 확인되지 않아 추가 확인 필요하므로 인포." "core dump 제한 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음"
  else
    set_good "core dump 제한 설정이 확인되므로 양호." "core dump 제한 설정이 확인되므로 양호." "$(echo "$ITEM_RAW" | head -n 3)"
  fi
}

# L-27 로깅 서비스 동작
check_l27() {
  set_item_meta "L-27" "로깅 서비스 동작" "시스템 로깅 서비스 동작 여부 확인" "systemctl is-active rsyslog|syslog-ng"
  if have_cmd systemctl; then
    ITEM_RAW="$(systemctl is-active rsyslog 2>/dev/null; systemctl is-active syslog-ng 2>/dev/null | head -n 2)"
  else
    ITEM_RAW="$(ps -ef 2>/dev/null | grep -E 'rsyslogd|syslog-ng' | grep -v grep | head -n 5)"
  fi
  if echo "$ITEM_RAW" | grep -Eq 'active|rsyslogd|syslog-ng'; then
    set_good "로깅 서비스가 동작 중이므로 양호." "로깅 서비스가 동작 중이므로 양호." "$(echo "$ITEM_RAW" | head -n 3)"
  elif [ -n "$ITEM_RAW" ]; then
    set_weak "로깅 서비스 동작이 확인되지 않으므로 취약." "로깅 서비스 동작이 확인되지 않으므로 취약." "$(echo "$ITEM_RAW" | head -n 3)"
  else
    set_info "로깅 서비스 상태가 확인되지 않아 추가 확인 필요하므로 인포." "로깅 서비스 상태가 확인되지 않아 추가 확인 필요하므로 인포." "상태 미확인"
  fi
}

# L-28 로그 파일 권한
check_l28() {
  set_item_meta "L-28" "주요 로그 파일 권한" "로그 파일 권한 보호 여부 확인" "stat -c '%a %U %G %n' /var/log/messages /var/log/secure /var/log/auth.log"
  ITEM_RAW="$(stat -c '%a %U %G %n' /var/log/messages /var/log/secure /var/log/auth.log 2>/dev/null | head -n 10)"
  if [ -z "$ITEM_RAW" ]; then set_info "주요 로그 파일이 확인되지 않아 추가 확인 필요하므로 인포." "주요 로그 파일이 확인되지 않아 추가 확인 필요하므로 인포." "파일 없음"; return; fi
  if echo "$ITEM_RAW" | awk '{if($1>640 || $2!="root") bad=1} END{exit bad}'; then
    set_good "주요 로그 파일 권한이 기준을 충족하므로 양호." "주요 로그 파일 권한이 기준을 충족하므로 양호." "$(echo "$ITEM_RAW" | head -n 3)"
  else
    set_weak "주요 로그 파일 권한이 기준을 충족하지 않으므로 취약." "주요 로그 파일 권한이 기준을 충족하지 않으므로 취약." "$(echo "$ITEM_RAW" | head -n 3)"
  fi
}

# L-29 홈 디렉터리 소유자
check_l29() {
  set_item_meta "L-29" "홈 디렉터리 소유자" "일반 사용자 홈 디렉터리 소유자 적정성 확인" 'awk -F: '\''$3>=1000{print $1":"$6}'\'' /etc/passwd'
  ITEM_RAW=""
  while IFS=: read -r user _ uid gid _ home _; do
    [ "$uid" -ge 1000 ] 2>/dev/null || continue
    [ -d "$home" ] || continue
    owner="$(stat -c '%U' "$home" 2>/dev/null || echo unknown)"
    [ "$owner" = "$user" ] || ITEM_RAW="${ITEM_RAW}${user}:${home}:owner=${owner}\n"
  done < /etc/passwd
  if [ -z "$ITEM_RAW" ]; then set_good "홈 디렉터리 소유자가 계정과 일치하므로 양호." "홈 디렉터리 소유자가 계정과 일치하므로 양호." "불일치 없음"; else set_weak "홈 디렉터리 소유자 불일치가 확인되므로 취약." "홈 디렉터리 소유자 불일치가 확인되므로 취약." "$(printf '%b' "$ITEM_RAW" | head -n 3)"; fi
}

# L-30 홈 디렉터리 권한
check_l30() {
  set_item_meta "L-30" "홈 디렉터리 권한" "일반 사용자 홈 디렉터리 과다 권한 확인" "stat -c '%a %n' <home>"
  ITEM_RAW=""
  while IFS=: read -r user _ uid _ _ home _; do
    [ "$uid" -ge 1000 ] 2>/dev/null || continue
    [ -d "$home" ] || continue
    perm="$(stat -c '%a' "$home" 2>/dev/null || echo 999)"
    if echo "$perm" | grep -Eq '^[0-9]+$' && [ "$perm" -gt 750 ]; then ITEM_RAW="${ITEM_RAW}${user}:${home}:perm=${perm}\n"; fi
  done < /etc/passwd
  if [ -z "$ITEM_RAW" ]; then set_good "홈 디렉터리 권한이 기준 이하이므로 양호." "홈 디렉터리 권한이 기준 이하이므로 양호." "초과 권한 없음"; else set_weak "홈 디렉터리 권한이 기준 초과이므로 취약." "홈 디렉터리 권한이 기준 초과이므로 취약." "$(printf '%b' "$ITEM_RAW" | head -n 3)"; fi
}

# L-31 root PATH 점검
check_l31() {
  set_item_meta "L-31" "root PATH 보안" "PATH 내 현재 디렉터리(.) 포함 여부 확인" "echo $PATH"
  ITEM_RAW="PATH=${PATH:-}"
  if echo ":${PATH:-}:" | grep -q '::\|:\.:\|^\.:\|:\.$'; then
    set_weak "PATH에 현재 디렉터리(.) 또는 빈 경로가 포함되어 있으므로 취약." "PATH에 현재 디렉터리(.) 또는 빈 경로가 포함되어 있으므로 취약." "$ITEM_RAW"
  else
    set_good "PATH에 현재 디렉터리(.) 또는 빈 경로가 포함되지 않으므로 양호." "PATH에 현재 디렉터리(.) 또는 빈 경로가 포함되지 않으므로 양호." "$ITEM_RAW"
  fi
}

# L-32 inetd/xinetd 사용 여부
check_l32() {
  set_item_meta "L-32" "inetd/xinetd 사용 여부" "레거시 슈퍼데몬 사용 여부 확인" "ps -ef | grep -E 'inetd|xinetd'"
  ITEM_RAW="$(ps -ef 2>/dev/null | awk '/inetd|xinetd/ && $0 !~ /grep -E/ {print}' | head -n 5)"
  if [ -z "$ITEM_RAW" ]; then
    set_good "inetd 또는 xinetd 프로세스가 확인되지 않으므로 양호." "inetd 또는 xinetd 프로세스가 확인되지 않으므로 양호." "프로세스 없음"
  else
    set_weak "inetd 또는 xinetd 프로세스가 확인되므로 취약." "inetd 또는 xinetd 프로세스가 확인되므로 취약." "$ITEM_RAW"
  fi
}

# L-33 NFS 서비스 노출
check_l33() {
  set_item_meta "L-33" "NFS 서비스 상태" "불필요한 NFS 서비스 동작 여부 확인" "systemctl is-active nfs-server"
  if have_cmd systemctl; then
    ITEM_RAW="$(systemctl is-enabled nfs-server 2>/dev/null; systemctl is-active nfs-server 2>/dev/null | head -n 2)"
  else
    ITEM_RAW="$(ps -ef 2>/dev/null | grep -E 'nfsd|rpc\.mountd' | grep -v grep | head -n 5)"
  fi
  if echo "$ITEM_RAW" | grep -Eq 'active|enabled|nfsd|rpc.mountd'; then
    set_info "NFS 서비스 사용 목적이 확인되지 않아 추가 확인 필요하므로 인포." "NFS 서비스 사용 목적이 확인되지 않아 추가 확인 필요하므로 인포." "$(echo "$ITEM_RAW" | head -n 3)"
  else
    set_good "NFS 서비스 동작이 확인되지 않으므로 양호." "NFS 서비스 동작이 확인되지 않으므로 양호." "미동작"
  fi
}

# L-34 FTP 익명접속 설정
check_l34() {
  set_item_meta "L-34" "FTP 익명접속 제한" "익명 FTP 허용 여부 확인" "grep 'anonymous_enable' /etc/vsftpd/vsftpd.conf"
  local file line
  file="$(first_existing_file /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null || true)"
  if [ -z "$file" ]; then ITEM_RAW="vsftpd 설정 파일 없음"; set_info "FTP 설정 파일이 확인되지 않아 추가 확인 필요하므로 인포." "FTP 설정 파일이 확인되지 않아 추가 확인 필요하므로 인포." "파일 없음"; return; fi
  line="$(grep -Ei '^[[:space:]]*anonymous_enable[[:space:]]*=' "$file" 2>/dev/null | tail -n 1)"; ITEM_RAW="$line"
  if [ -z "$line" ]; then set_info "anonymous_enable 설정이 확인되지 않아 추가 확인 필요하므로 인포." "anonymous_enable 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음";
  elif echo "$line" | grep -Eiq '=[[:space:]]*NO'; then set_good "anonymous_enable이 NO로 설정되어 있으므로 양호." "anonymous_enable이 NO로 설정되어 있으므로 양호." "$line";
  else set_weak "anonymous_enable이 NO가 아니므로 취약." "anonymous_enable이 NO가 아니므로 취약." "$line"; fi
}

# L-35 패키지 서명 검증 설정
check_l35() {
  set_item_meta "L-35" "패키지 서명 검증" "패키지 설치 시 서명 검증 사용 여부 확인" "rpm/apt/apk 설정 확인"
  case "$OS_FAMILY" in
    rhel)
      ITEM_RAW="$(grep -Ehi '^[[:space:]]*gpgcheck[[:space:]]*=' /etc/yum.conf /etc/yum.repos.d/*.repo 2>/dev/null | head -n 20)"
      if [ -z "$ITEM_RAW" ]; then set_info "gpgcheck 설정이 확인되지 않아 추가 확인 필요하므로 인포." "gpgcheck 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음";
      elif echo "$ITEM_RAW" | grep -Eiq '=[[:space:]]*0'; then set_weak "gpgcheck가 0으로 설정되어 있으므로 취약." "gpgcheck가 0으로 설정되어 있으므로 취약." "$(echo "$ITEM_RAW" | grep -Ei '=[[:space:]]*0' | head -n 3)";
      else set_good "gpgcheck가 1로 설정되어 있으므로 양호." "gpgcheck가 1로 설정되어 있으므로 양호." "$(echo "$ITEM_RAW" | grep -Ei '=[[:space:]]*1' | head -n 3)"; fi
      ;;
    debian)
      ITEM_RAW="$(grep -Ehi '^[[:space:]]*deb[[:space:]]+' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | head -n 20)"
      if [ -z "$ITEM_RAW" ]; then set_info "APT 저장소 설정이 확인되지 않아 추가 확인 필요하므로 인포." "APT 저장소 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음";
      elif echo "$ITEM_RAW" | grep -Eqi 'trusted=yes'; then set_weak "APT 저장소에 trusted=yes가 확인되므로 취약." "APT 저장소에 trusted=yes가 확인되므로 취약." "$(echo "$ITEM_RAW" | grep -Ei 'trusted=yes' | head -n 3)";
      else set_good "APT 저장소에 trusted=yes가 확인되지 않으므로 양호." "APT 저장소에 trusted=yes가 확인되지 않으므로 양호." "$(echo "$ITEM_RAW" | head -n 3)"; fi
      ;;
    alpine)
      ITEM_RAW="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/apk/repositories 2>/dev/null | head -n 20)"
      if [ -z "$ITEM_RAW" ]; then set_info "APK 저장소 설정이 확인되지 않아 추가 확인 필요하므로 인포." "APK 저장소 설정이 확인되지 않아 추가 확인 필요하므로 인포." "설정 없음";
      elif echo "$ITEM_RAW" | grep -Eq '^http://'; then set_weak "APK 저장소에 http가 포함되어 있으므로 취약." "APK 저장소에 http가 포함되어 있으므로 취약." "$(echo "$ITEM_RAW" | grep '^http://' | head -n 3)";
      else set_good "APK 저장소가 https를 사용하므로 양호." "APK 저장소가 https를 사용하므로 양호." "$(echo "$ITEM_RAW" | head -n 3)"; fi
      ;;
    *)
      ITEM_RAW="OS_FAMILY=$OS_FAMILY"
      set_info "패키지 서명 검증 기준이 확인되지 않아 추가 확인 필요하므로 인포." "패키지 서명 검증 기준이 확인되지 않아 추가 확인 필요하므로 인포." "$ITEM_RAW"
      ;;
  esac
}

# L-36 시간 동기화 서비스
check_l36() {
  set_item_meta "L-36" "시간 동기화 서비스" "시간 동기화 서비스 동작 여부 확인" "systemctl is-active chronyd|ntpd|systemd-timesyncd"
  if have_cmd systemctl; then
    ITEM_RAW="$(systemctl is-active chronyd 2>/dev/null; systemctl is-active ntpd 2>/dev/null; systemctl is-active systemd-timesyncd 2>/dev/null | head -n 5)"
  else
    ITEM_RAW="$(ps -ef 2>/dev/null | grep -E 'chronyd|ntpd|timesyncd' | grep -v grep | head -n 5)"
  fi
  if echo "$ITEM_RAW" | grep -Eq 'active|chronyd|ntpd|timesyncd'; then
    set_good "시간 동기화 서비스 동작이 확인되므로 양호." "시간 동기화 서비스 동작이 확인되므로 양호." "$(echo "$ITEM_RAW" | head -n 3)"
  elif [ -n "$ITEM_RAW" ]; then
    set_weak "시간 동기화 서비스 동작이 확인되지 않으므로 취약." "시간 동기화 서비스 동작이 확인되지 않으므로 취약." "$(echo "$ITEM_RAW" | head -n 3)"
  else
    set_info "시간 동기화 서비스 상태가 확인되지 않아 추가 확인 필요하므로 인포." "시간 동기화 서비스 상태가 확인되지 않아 추가 확인 필요하므로 인포." "상태 미확인"
  fi
}

########################################
# 9. run_all_checks 함수
########################################
run_all_checks() {
  local i fn
  for i in $(seq -w 1 36); do
    fn="check_l${i}"
    if declare -f "$fn" >/dev/null 2>&1; then
      "$fn"
      record_result
    else
      set_item_meta "L-${i}" "미구현 항목" "항목 누락 방지" "내부 함수 확인"
      ITEM_RAW="함수 ${fn} 없음"
      set_info "점검 함수가 확인되지 않아 추가 확인 필요하므로 인포." "점검 함수가 확인되지 않아 추가 확인 필요하므로 인포." "$ITEM_RAW"
      record_result
    fi
  done
}

########################################
# 10. main 함수
########################################
main() {
  detect_os
  init_output
  run_all_checks

  echo "점검이 완료되었습니다."
  echo "상세 로그: ${DETAIL_LOG}"
  echo "요약 결과: ${SUMMARY_TSV}"
}

main "$@"
