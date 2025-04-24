1.10.26 버전 기준이며, 상위 버전은 ethash(Ethereum 1.0을 위해 만들어진 PoW 알고리즘)가 작동하지 않는다.

체인 스토리지 초기화: 
    geth init --datadir data genesis.json

Geth 실행: 
    geth --datadir data --http --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net" (console)

계정 생성: 
    geth --datadir data account new 

계정 목록: 
    geth --datadir data account list

계정 비밀번호 변경: 
    geth --datadir data account update {인덱스}

Geth 콘솔 명령어: 
    geth console: Geth 노드를 실행하면서 동시에 JavaScript 콘솔에 접속하는 방법이다.
    geth attach http://127.0.0.1:8545 : 이미 실행 중인 Geth 노드에 RPC 서버가 활성화되어 있을 때, 해당 노드에 연결하는 방법이다.

Geth 실행 설정 파일을 지정:
    geth --config geth-config.toml

블록체인 데이터 디렉토리를 지정:
    geth --datadir data

노드의 동기화 방식을 지정:
    geth --syncmode "full": 전체 블록체인 데이터를 모두 다운로드하고 검증한다. 가장 안전하지만 시간이 오래 걸린다.
    geth --syncmode "snap": 전체 블록체인 데이터의 다운로드 대신, 최신 상태의 스냅샷을 다운로드하여 빠르게 노드를 동기화한다.
    geth --syncmode "light": 경량 노드로, 전체 블록체인 데이터를 저장하지 않고 필요한 정보만 요청하여 동작한다.

Geth에서 가비지 컬렉션(Garbage Collection) 모드 설정:
    geth --gcmode "archive": 체인 데이터를 완전히 저장하여, 과거의 상태를 조회하거나 분석하는 데 유용하다.

네트워크에 연결하여 Geth 실행:
    geth --mainnet
    geth --goerli
    geth --sepolia

Geth 실행 시, 계정을 잠금/해제:
    geth --datadir data --unlock 0 
    geth --datadir data --unlock 0 --password password: 비밀번호 파일로 잠금 해제
    geth --datadir data --unlock 0 --password password --allow-insecure-unlock: 계정을 잠금 해제할 때 보안 검증을 생략하거나 비보안 방식으로 허용

HTTP 프로토콜을 통해 노드와 통신:
    geth --http: HTTP RPC 서버 활성화
    geth --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net": API를 활성화
    geth --http.corsdomain "*": CORS(교차 출처 리소스 공유) 정책을 설정하는 것으로, 모든 도메인(*)에서의 요청을 허용
    geth --http.addr "0.0.0.0": HTTP 서버가 모든 네트워크 인터페이스(0.0.0.0)에서 요청을 수신하도록 설정
    geth --http.port "8545: HTTP RPC 서버가 사용할 포트 번호를 지정(기본 포트: 8545)

WebSocket 프로토콜을 통해 노드와 통신:
    geth --ws
    geth --ws.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net"
    geth --ws.origins "*"
    geth --ws.addr "0.0.0.0"
    geth --ws.port "8546

블록넘버 확인:
    eth.blockNumber

마이닝(채굴) 시작/종료:
    miner.start(1)
    miner.stop()

블록체인 데이터 내보내기(Geth 종료상태):
    geth --datadir data export backup 0 {8}

블록체인 데이터 삭제:
    geth --datadir data removedb
    eth.blockNumber 로 재확인
    /geth 폴더 삭제

블록체인 데이터 가져오기(Geth 실행상태):
    geth --datadir data import backup

명령어 모음:
    띄어쓰기 두번 + 탭
