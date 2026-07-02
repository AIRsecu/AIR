# IR Automation

실시간 DevSecOps 보안 운영 자동화 시스템의 IR(Incident Response) 모듈

## 폴더 구조
- config/: 설정 파일
- ir/detector/: 공격 탐지
- ir/analyzer/: 위험도 분석
- ir/responder/: 자동 대응
- ir/notifier/: Discord 알림
- playbook/: NIST IR 4단계 플레이북

## 실행 방법
```
# 팀 레포 루트에서
poetry install
cp ir-automation/.env.example ir-automation/.env
# .env에 Discord Webhook URL 입력
```
