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

<img src="https://github.com/user-attachments/assets/787034c8-bf10-466f-afe9-8116bcd33349" width="450">

<img src="https://github.com/user-attachments/assets/7ce94486-e255-4afb-b5d3-9c8eb5510351" width="450">

<img src="https://github.com/user-attachments/assets/7ce94486-e255-4afb-b5d3-9c8eb5510351" width="450">

<img src="https://github.com/user-attachments/assets/e71af3fc-de42-493d-926a-34bb4c14df63" width="450">
