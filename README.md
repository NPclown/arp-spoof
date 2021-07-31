### 과제
arp spoofing 프로그램을 구현하라.

### 실행
```
syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]
sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2
```

### 상세


- 이전 과제(send-arp)를 다 수행하고 나서 이번 과제를 할 것.
- "arp-spoofing.ppt"의 내용을 숙지할 것.
- 코드에 victim, gateway라는 용어를 사용하지 말고 sender, target(혹은 receiver)라는 단어를 사용할 것.
- sender에서 보내는 spoofed IP packet을 attacker가 수신하면 이를 relay하는 것 코드를 구현할 것.
- sender에서 infect가 풀리는(recover가 되는) 시점을 정확히 파악하여 재감염시키는 코드를 구현할 것.
- (sender, target) flow를 여러개 처리할 수 있도록 코드를 구현할 것.
- 가능하다면 주기적으로 ARP infect packet을 송신하는 기능도 구현해 볼 것.
- attacker, sender, target은 물리적으로 다른 머신이어야 함. 가상환경에서 Guest OS가 attacker, Host OS가 sender가 되거나 하면 안됨.
- Vmware에서 Guest OS를 attacker로 사용할 때 sender로부터의 spoofed IP packet이 보이지 않을 경우 vmware_adapter_setting 문서를 참고할 것.
- Host OS의 네트워크를 사용하지 않고 별도의 USB 기반 네트워크 어댑터를 Guest OS에서 사용하는 것을 추천. 다이소에서 5000원으로 구매할 수 있음. - https://www.youtube.com/watch?v=f8baVYPM9Pc



### 환경셋팅
- Host 환경이 무선랜 상태이라면 Guest 네트워크를 어뎁터에 브리지로 설정하여도 공유기 arp 테이블에서는 Guest의 Mac가 아니라 Host의 Mac로 기록된다. 그래서 Host는 유선랜 상태여야 Mac을 구분하여 판단한다. (추천)
- 두번째 방법으로는 Guest 환경에 직접 WLAN을 올리는 것이다. usb wlan 필터를 추가하여 Guest 내부에서 와이파이를 잡아준다. 그러면 Guest의 Mac주소는 WLAN의 Mac이 되고 실습을 진행할 수 있다. (가끔씩 패킷을 잘 못잡음)
