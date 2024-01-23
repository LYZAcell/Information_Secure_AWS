import socket
import nmap


#1. SSH 버전을 가져오는 코드
# ssh port : 22번

def get_ssh_ver(server_ip, server_port=22):
    try:
        # 포트 스캔
        nm = nmap.PortScanner()
        # 핑을 받지 않는 서버가 있어 예외처리하였다.
        nm.scan(hosts=server_ip, ports=str(server_port), arguments="-Pn")

        #22번 포트 열림여부 검사
        if server_ip in nm.all_hosts():
            port_data = nm[server_ip]["tcp"][server_port]
            if port_data["state"] == "open":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                # 타임아웃시간 5초 설정
                sock.settimeout(5)
                # 소킷 및 포트 연결
                sock.connect((server_ip, server_port))

                banner = sock.recv(1024).decode('utf-8')

                # ssh 버전 추출하기
                ssh_version = banner.split(' ', 2)[1].strip()

                print(f"SSH 버전: {ssh_version}")
                # 소켓을 꼭 닫아줘야한다.
                sock.close()
                
            # 테스트 서버의 경우 icmp가 filtered된 경우가 있어 포트 검사를 하여 예외처리해주었다. 
            elif port_data["state"] == "filtered":
                print(f"SSH: port 22 filtered")
            else:
                print(f" SSH: 연결없음")
        else:
            print(f"{server_ip}에 대해 {server_port} 판명이 불가합니다.")

    except socket.timeout:
        print(f"SSH: 연결시간 timed out {server_ip}:{server_port}")
    except ConnectionRefusedError:
        print(f"SSH: 연결거부 {server_ip}:{server_port}")
    except Exception as e:
        print(f"SSH: Error: {e}")
        
        
        
        
# 2. 웹서버 정보 가져오기
# 웹포트: 80번
def get_web_server(server_ip, server_port=80):
    try:
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 타임아웃:5초 설정
        sock.settimeout(5)

        # 아이피와 80번에 연결해주기
        sock.connect((server_ip, server_port))

        # HTTP request보내기. encoding에러가 깨져서 utf-8넣어줌
        http_request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(server_ip)
        sock.sendall(http_request.encode('utf-8'))
        http_answer = sock.recv(1024).decode('utf-8')

        # 헤더 정보에서 뽑은 웹서버 정보n
        server_info = get_server_info(http_answer)
        print(f"웹서버: {server_info}")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        # 소켓 닫기
        sock.close()
        
# 2.5. 헤더 정보 추출하기
def get_server_info(http):
    header = http.find("Server:")
    if header != -1:
        header_end = http.find("\r\n", header)
        server_info = http[header + len("Server:"):header_end].strip()
        return server_info
    else:
        return "Unknown"
    
    
# 3.운영체제 정보 가져오기
def get_os_info(server_ip):
    try:
        nm = nmap.PortScanner()

        # 테스트 서버 2의 window를 추출하기 위해 핑을 뺐다.
        nm.scan(hosts=server_ip, arguments='-O -Pn')

        if server_ip in nm.all_hosts():
            if 'osmatch' in nm[server_ip]:
                os_info = nm[server_ip]['osmatch'][0]['osclass'][0]['osfamily']
                os_version = nm[server_ip]['osmatch'][0]['osclass'][0]['osgen']
                print(f"OS: {os_info} {os_version}")
            else:
                print("OS정보 알 수 없음")
        else:
            print("호스트 찾을 수 없음")

    except Exception as e:
        print(f"Error: {e}")
        
    
# 4. DB 정보 가져오기: Mysql에 대해서만 가져왔다.

def check_DB(server_ip):
    nm = nmap.PortScanner()
    # mtsql검사. 포트 3306. 핑에 막혀 조사가 안되는 경우가 있어서 ping이 아니도록 검사하였다.
    nm.scan(hosts=server_ip, arguments="-p 3306 -Pn")

    if server_ip in nm.all_hosts():
        port_data = nm[server_ip]["tcp"][3306]
        if port_data["state"] == "open":
            print(f"DB: MySQL")
            
        #3306이 filtered되어있어 알 수 없는 경우
        elif port_data["state"] == "filtered":
            print(f"DB: 3306port filtered")
        else:
            print(f"DB: 없음")
    else:
        print(f"DB:{server_ip}의 MySQL정보 알 수 없음 ")

def main():
    server_ip = input("IP를 입력해주세요: ")
    print("\n")
    print("분석 결과")
    get_os_info(server_ip)
    get_web_server(server_ip)
    check_DB(server_ip)
    get_ssh_ver(server_ip)
    

if __name__ == "__main__":
    main()