# cloud-back-server

Spring Cloud Gateway 기반 API 게이트웨이입니다. JWT를 검증하고 백엔드 서비스로 요청을 라우팅하며, 인증된 사용자 헤더를 downstream 서비스로 전달합니다.

## 역할
- `/auth/**`, `/oauth2/**`, `/login/**` 라우팅
- `zeroq`, `muse`, `semo` API 라우팅
- JWT 검증
- 요청/응답 로깅 필터 적용

## 포트
- `8080`

## 실행
```bash
./gradlew :cloud-back-server:bootRun
```

## 빌드 / 테스트
```bash
./gradlew :cloud-back-server:compileJava
./gradlew :cloud-back-server:test
```

## 공개 경로
- `/auth/login`
- `/auth/refresh`
- `/oauth2/**`
- `/login/**`
- `/.well-known/**`
- `/actuator/**`
- `POST /api/users`
- `GET /api/muse/v1/home`
- `GET /api/muse/v1/overview`
- `GET /api/muse/v1/contests/**`
- `GET /api/muse/v1/gallery/**`
- `GET /api/muse/v1/artworks/**`

## 라우팅 대상
- `lb://auth-back-server`
- `lb://zeroq-back-service`
- `lb://zeroq-back-sensor`
- `lb://semo-back-service`
- `lb://muse-back-service`

## 참고
- JWT secret은 `CLOUD_JWT_SECRET`로 주입합니다.
- CORS 허용 origin은 현재 `3000`~`3003` 프론트 개발 포트 위주로 설정돼 있습니다.
- 인증 후 사용자 정보는 필터에서 downstream 헤더로 전달됩니다.
