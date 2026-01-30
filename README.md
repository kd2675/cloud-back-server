# cloud-back-server

API 게이트웨이 서비스입니다. 요청 라우팅과 JWT 검증을 수행하며, 인증 성공 시 사용자 정보를 헤더에 주입합니다.

## 역할
- 백엔드 서비스 라우팅
- JWT 검증 및 `X-User-*` 헤더 주입

## 포트
- 8080

## 실행
```bash
./gradlew cloud-back-server:bootRun
```

## 주요 노트
- 공개 경로 외 모든 요청은 `Authorization: Bearer <token>`이 필요합니다.
- 인증 성공 시 `X-User-Id`, `X-User-Name`, `X-User-Role` 헤더가 주입됩니다.
- 유레카 클라이언트로 동작합니다.
