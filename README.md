# WHS_PCAP-Programming

## 프로젝트 소개

- 이 프로젝트는 PCAP 라이브러리를 활용하여 네트워크 패킷을 캡처하고, TCP 패킷과 HTTP 트래픽을 분석하여 출력하는 프로그램을 개발하는 것이 목표입니다.

<br>

## PCAP 라이브러리 설치와 과정
- sudo apt update
- sudo apt install libpcap-dev
- vi network_capture.c
- gcc network_capture.c -o network_capture -lpcap
- sudo ./network_capture

<br>

## 결과
