# 구현 목표
스프링부트에 JWT 방식으로 로그인 인증을 진행하는 스프링 시큐리티를 적용하며<br>
인증/인가를 구현하고 회원정보 저장(영속성)은 MySQL 데이터베이스를 활용하여 구현한다.<br>

로그인은 JWT 를 사용하여 stateless 로 관리한다 <br>

## 구현
- 인증: 로그인
- 인가: 경로별 접근 권한
- 회원가입

### 프로젝트 버전
- SpringBoot 3.3.1
- JDK 17
- Spring Security 6.2
- Spring Data JPA
- MySQL
- Thymeleaf
- Intellij Ultimate

### REF
https://www.youtube.com/watch?v=NPRh2v7PTZg&list=PLJkjrxxiBSFCcOjy0AAVGNtIa08VLk1EJ