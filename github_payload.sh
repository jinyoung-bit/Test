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
    if [ -n "$LOG_FILE" ]; then
        eval "$command" 2>&1 | tee -a "$LOG_FILE"
    else
        eval "$command" 2>&1
    fi

    if [ $? -eq 0 ]; then
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
    # 예시 (이 부분은 사용자에게 안내하는 용도이므로 실제 명령 실행 아님)
    # sudo userdel -r EDRTestUser_linux
    # sudo userdel -r TestUser2
    # sudo systemctl stop edr-test.service
    # sudo systemctl disable edr-test.service
    # sudo rm /etc/systemd/system/edr-test.service
    # sudo systemctl daemon-reload
    # crontab -l | grep -v 'EDR Test Cron Job executed' | crontab -
    # sudo systemctl start firewalld
    # sudo firewall-cmd --reload
    # sudo iptables -F; sudo iptables -X; sudo iptables -t nat -F; sudo iptables -t nat -X; sudo iptables -P INPUT ACCEPT
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
# atomic-cli 없이 직접 명령어 실행
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
    # Base64 인코딩된 문자열을 수정하여 /tmp/$TEST_DIR_NAME/message.txt에 저장하도록 변경
    # 'echo Hidden message > $TEST_DIR/message.txt' 를 base64 인코딩한 값:
    # echo 'echo '\''Hidden message'\'' > '\'${TEST_DIR}'/message.txt' | base64
    # 결과: ZWNobyAnSGlkZGVuIG1lc3NhZ2UnID4gJ3RlbXAvRURSX0FUVEFDS19URVNUXzE3NTMzMzg2OTgv/bWVzc2FnZS50eHQn
    # 이 부분은 스크립트 실행 시 TEST_DIR의 동적인 값을 가져오기 어려움.
    # 안전하게 $TEST_DIR/message.txt 로 저장하도록 단순화.
    # EDR은 base64 명령 실행 자체를 탐지해야 함.
    run_command "python3 -c \"import base64; import os; os.system(base64.b64decode(b'ZWNobyAnSGlkZGVuIG1lc3NhZ2UnID4gJyRuYW1lLnB5Jyc=').decode('utf-8'))\"" "Python Base64 실행"
    log_message "${YELLOW}[정보]${NC}" "T3 테스트는 '/tmp' 디렉토리에 'Hidden message' 파일 생성 시도를 모의합니다. EDR은 Base64 명령 실행 자체를 탐지해야 합니다."
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
CRON_JOB="@reboot echo 'EDR Test Cron Job executed' >> $TEST_DIR/cron_output.txt"
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

log_message "${GREEN}[완료]${NC}" "모든 EDR 탐지 테스트 스크립트 실행 완료."
log_message "${YELLOW}[정리 안내]${NC}" "생성된 파일 및 디렉토리, 계정, 서비스, 크론탭 작업은 이 스크립트가 자동으로 삭제하지 않습니다. 수동으로 삭제해야 합니다."

exit 0