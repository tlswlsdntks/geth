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

Geth 실행(모든 도메인, 모든 네트워크에서의 요청 및 수신 허용)
    geth --datadir data --http --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net" --http.addr "0.0.0.0" --http.corsdomain "*" (console)

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

블록체인 데이터 가져오기(Geth 종료상태):
    geth --datadir data import backup

명령어 모음:
    띄어쓰기 두번 + 탭

어드레스:
    이더리움 어드레스는 이더리움 네트워크에서 사용자의 계정을 식별하는 고유한 주소이다.
    보통 42자의 16진수 문자열로 구성되어 있으며, '0x'로 시작한다.
    이 주소를 통해 이더리움 기반의 토큰이나 스마트 계약과의 거래가 이루어지며, 개인의 자산을 안전하게 관리하는 데 중요한 역할을 한다.

어드레스(계좌의 "주소") 생성:
    personal.newAccount(0000)

키 스토어(계좌를 안전하게 관리하는 "지갑")
    UTC--2025-04-24T07-31-29.582961800Z--1f6f5facf663e147809c02e56495ee9173db10ae
    {
    "address": "1f6f5facf663e147809c02e56495ee9173db10ae", // address: 암호화된 데이터 또는 계좌 주소와 관련된 식별자
    "crypto": { // crypto: 암호화 관련 정보를 담고 있는 객체
        "cipher": "aes-128-ctr", // cipher: 사용된 암호화 알고리즘(여기서는 AES-128-CTR)
        "ciphertext": "a6a615f6dded661ade5176195d3637b63eeb12fcb74dec6f49a9bd9c73017c97", // ciphertext: 암호화된 실제 데이터
        "cipherparams": { // cipherparams: 암호화에 사용된 초기화 벡터(IV) 정보
            "iv": "d9a8ba751bb8c7b769f66c3e780614e9" // iv: 초기화 벡터 값
        },
        "kdf": "scrypt", // kdf: 키 파생 함수(여기서는 scrypt)
        "kdfparams": { // kdfparams: 키 파생 함수에 필요한 매개변수
            "dklen": 32, // dklen: 파생 키의 길이(바이트 단위)
            "n": 262144, // n: scrypt 알고리즘의 CPU/메모리 비용 매개변수
            "p": 1, // p: scrypt의 병렬 처리 파라미터
            "r": 8, // r: scrypt의 블록 크기
            "salt": "621d80dde52903e95b4203351ac7ce330c6a13d617f46384d2a09f2b0bfd3f9f" // salt: 솔트 값
        },
        "mac": "9125457da28fb4bb39118601d668ad6bad856118a91b11a337e9ea5b721a7e94" // mac: 메시지 인증 코드, 데이터 무결성 검증용
    },
    "id": "3bef7418-7be2-4db9-af65-6a7790f1c8d6", // id: 이 데이터의 고유 식별자(UUID 형식)
    "version": 3 // version: 데이터 구조의 버전 번호
}