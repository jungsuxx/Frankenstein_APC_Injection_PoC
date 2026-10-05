# Frankenstein_APC_Injection_PoC

VirtualAllocEx나 WriteProcessMemory 없이 이미 실행 중인 프로세스에 셸코드를 인젝션하는 기법입니다.
새로운 메모리를 할당하는 대신 공유 섹션 오브젝트를 생성해서 타겟 프로세스에 RX로 직접 매핑합니다.
APC는 NtQueueApcThreadEx2 Special APC로 큐잉하며 스레드가 alertable 상태일 필요가 없습니다.
셸코드 슬롯은 의도적으로 비워져 있습니다.

## 사용법

컴파일 후 EXE를 파라미터 없이 실행하면 됩니다.

## 동작 순서

* PEB를 직접 워크해서 kernel32 / KernelBase / ntdll 베이스 주소를 가져옵니다.
* Export 테이블 해시 탐색으로 필요한 API를 전부 resolve합니다. GetProcAddress, GetModuleHandle 없음.
* ntdll stub에서 시스콜 서비스 번호(SSN)를 추출합니다. 훅된 stub은 Hell's Gate + Halo's Gate 보간으로 처리합니다.
* 커널 ReturnAddress 체크를 통과하기 위해 ntdll 가젯을 경유하는 간접 시스콜 트램폴린을 구성합니다.
* NtGetNextProcess로 실행 중인 프로세스를 열거합니다. Toolhelp 스냅샷 없음.
* ACG(ProhibitDynamicCode)가 걸린 프로세스는 스킵합니다. NtMapViewOfSection도 ACG에서 차단됩니다.
* NtCreateSection으로 pagefile 기반 섹션을 생성합니다.
* 로컬에 RW 뷰를 매핑해서 RC4 복호화된 페이로드를 기록한 뒤 언맵합니다.
* 타겟 프로세스에 동일 섹션의 RX 뷰를 매핑합니다. 타겟에 RWX 영역이 생기지 않습니다.
* NtGetNextThread로 스레드를 가져와서 매핑된 뷰 주소로 Special User APC를 큐잉합니다.

## 셸코드

rc4_key로 RC4 암호화한 셸코드를 enc_shellcode[]에 넣으면 됩니다.
셸코드는 고정 베이스 주소에 의존하지 않는 PIC(position-independent) 형태여야 합니다.

## 빌드

MSVC 전용입니다.


Requires Windows 11 / Server 2022+ for NtQueueApcThreadEx2 Special APC support.


For educational purposes only.
