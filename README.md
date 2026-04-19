# CS330 - Operating Systems and Lab

KAIST CS330 운영체제 수업 — [Pintos-KAIST](https://casys-kaist.github.io/pintos-kaist/) 기반 OS 구현 (Team 76)

## 구현 내용

Pintos 교육용 x86 운영체제를 단계적으로 확장한 결과물입니다.

- **Threads**: 우선순위 스케줄링, 세마포어, 락, 조건 변수
- **User Programs**: 시스템 콜, 사용자 프로세스 실행, 인자 전달
- **Virtual Memory**: 페이지 테이블, 요구 페이징, 스택 증가
- **File System**: 파일 시스템 구현 및 확장

## 빌드

```bash
./install.sh
make
```

## 참고

- [Pintos-KAIST 매뉴얼](https://casys-kaist.github.io/pintos-kaist/)
