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
    geth --datadir data --unlock 0 --password password --allow-insecure-unlock: 보안상 위험이 있을 수 있는 계정 잠금 해제(특히 RPC를 통해 원격에서 잠금 해제하는 경우)를 허용

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

Geth 실행(모든 도메인, 네트워크에서의 요청 및 수신 허용)
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
    geth 폴더 삭제

블록체인 데이터 가져오기(Geth 종료상태):
    geth --datadir data import backup

명령어 모음:
    띄어쓰기 두번 + 탭

어드레스:
    이더리움 어드레스는 이더리움 네트워크에서 사용자의 계정을 식별하는 고유한 주소이다.
    보통 42자의 16진수 문자열로 구성되어 있으며, '0x'로 시작한다.
    이 주소를 통해 이더리움 기반의 토큰이나 스마트 계약과의 거래가 이루어지며, 개인의 자산을 안전하게 관리하는 데 중요한 역할을 한다.

어드레스(계좌의 "주소") 생성:
    personal.newAccount("0000")
    일반적으로 비밀번호를 입력하는 부분은 문자열로 입력해야 하며, 숫자만 넣는 경우 오류가 발생할 수 있다.

키 스토어(계좌를 안전하게 관리하는 "지갑")
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

현재 노드의 기본 계정 또는 채굴 계정:
    eth.coinbase

노드에 저장된 모든 계정 목록:
    eth.accounts

블록 번호 n번에 해당하는 블록의 정보:
    eth.getBlock(n)
    {
        difficulty: 131648, // 블록 채굴 난이도
        extraData: "0xda83010a1a846765746888676f312e31382e358777696e646f7773", // 블록에 포함된 임의 데이터
        gasLimit: 8078455, // 블록에 허용된 최대 가스량
        gasUsed: 0, // 실제 사용된 가스량 (이 경우 0)
        hash: "0xc4b7ea6c09825f97d7fa96ced3019124ca603805920a627ddec9fa9296bc05c4", // 블록의 고유 식별값
        logsBloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", // 로그 검색을 위한 필터
        miner: "0x0c33043f0926e2e2467fca96117ebefbf86d660b", // 블록을 채굴한 사람 또는 노드
        mixHash: "0x63ade33c2a1c4c124de9b3bc376ebadbdd8baecea3f13b41663d9bed9987c498", // 작업 증명에 사용되는 값
        nonce: "0x74fe754386698a2c", // 채굴 난이도 조정을 위한 값
        number: 10, // 블록의 순서 (이 경우 10번째 블록)
        parentHash: "0xef6b3b8927a4414afcbd887c9e297f22c1f88e7726198fe9fdc227f9ac1c474e", // 이전 블록의 해시
        receiptsRoot: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421", // 트랜잭션 영수증의 Merkle 루트
        sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347", // 삼촌 블록의 해시
        size: 538, // 블록 크기 (바이트 단위)
        stateRoot: "0xde451589ca6dcf03b0d6fa8fef689abfd10239801ff2d833eb45e23242ab6cc4", // 현재 상태의 Merkle 루트
        timestamp: 1745652592, // 블록 생성 시간 (유닉스 시간)
        totalDifficulty: 1313601, // 지금까지 채굴된 전체 난이도
        transactions: [], // 포함된 트랜잭션 목록 (이 경우 없음)
        transactionsRoot: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421", // 트랜잭션 Merkle 루트
        uncles: [] // 포함된 삼촌 블록 목록 (이 경우 없음)
    }

Merkle 루트:
    여러 데이터를 각각 해시(암호화된 값)로 바꾸고, 이 해시들을 계층적으로 연결해서 최상단에 하나의 루트 해시값을 만든다.
    이 루트 해시값만 보면 전체 데이터가 변했는지 쉽게 확인할 수 있어서, 주로 블록체인에서 데이터 무결성을 검증하는 데 사용된다.

geth 코드 - 블록의 구조 확인:
    go-ethereum\core\types\block.go, line: 206

엉클 블록:
    채굴자가 정식 블록(메인 체인에 포함된 블록)을 채굴하는 것 외에, 경쟁 과정에서 유효하지만 최종 블록으로 채택되지 않은 블록을 의미한다.
    이더리움 1.0에서는 엉클 블록 채굴자에게도 일정 비율의 보상(75%)이 지급되어, 네트워크의 안정성과 참여를 유도하는 중요한 역할

블록 분기(Fork):
    블록체인 네트워크에서 기존의 블록체인에서 분리되어 새로운 체인 또는 버전이 만들어지는 현상이다.
    네트워크 업그레이드, 규칙 변경, 버그 수정, 또는 커뮤니티 간의 합의에 따라 발생할 수 있다.

소프트 포크(Soft Fork): 
    기존 규칙과 호환되며, 일부 노드만 업데이트해도 네트워크 전체에 영향을 미치지 않는 변경
    
하드 포크(Hard Fork): 
    기존 규칙과 호환되지 않으며, 기존 체인과 분리되어 별개의 체인(혹은 네트워크)이 형성된다.
    예를 들어, 이더리움의 이더리움 클래식(Ethereum Classic)과 이더리움(ETH)처럼, 하나의 체인에서 분리되어 두 개의 체인이 존재하게 된 경우를 의미한다.

합의 알고리즘:
    1. Ethash
        이더리움 네트워크에서 사용하는 작업 증명(Proof of Work, PoW) 알고리즘이다.
        메모리 집약적(Memory-hard) 알고리즘으로, ASIC보다 GPU에 적합하게 설계되어 있다.
            ASIC(Application-Specific Integrated Circuit): 특정 용도에 맞게 설계된 맞춤형 집적회로를 의미한다.
            채굴용 ASIC: 비트코인이나 이더리움 채굴에 특화된 ASIC 칩, 이는 GPU보다 훨씬 빠르고 효율적으로 채굴이 가능하다.
        블록 생성 시 난이도 조절과 함께 무작위 데이터(캐시와 DAG)를 사용하여 채굴 난이도를 조절한다.
            캐시(Cache): 캐시는 데이터를 빠르게 접근하기 위해 일시적으로 저장하는 저장소이다.
            DAG(Directed Acyclic Graph, 방향성 비순환 그래프): 노드와 간선으로 구성된 구조로, 순서가 정해진 작업이나 데이터 흐름을 표현하는 데 사용된다.
    2. Beacon
        Beacon는 이더리움 2.0(이더리움의 업그레이드 버전)에서 사용하는 합의 프로토콜인 Beacon Chain과 관련된 용어이다.
            Beacon Chain: 이더리움 2.0의 핵심 체인으로, 검증자들의 상태와 합의 상태를 관리한다.
        지분 증명(Proof of Stake, PoS) 기반으로, 검증자들이 블록을 제안하고 검증하는 역할을 수행한다.
    3. Clique
        이더리움 기반의 프라이빗 또는 퍼블릭 네트워크에서 사용하는 권한 증명(Proof of Authority, PoA) 합의 알고리즘이다.
        네트워크 참여자가 신뢰할 수 있는 검증자들로 제한되어 있어, 보안성과 신뢰성을 높였다.

metamask 에 rpc 연결:
    1. Geth 실행(채굴 수행 설정, 계정 잠금 해제):
        geth --datadir data --http --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net" --mine --miner.threads "1" --unlock 0 --password password --allow-insecure-unlock
    2. metamask 확장 프로그램 설치
    3. metamask 회원가입/로그인
    2. 테스트 네트워크 표시 선택:
        chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/home.html#settings/advanced
    4. metamask 사용자 지정 네트워크 추가:
        네트워크 이름:
            테스트 넷
        기본 RPC URL:
            127.0.0.1:8545
        체인 ID:
            12345
        통화 기호:
            tETH
    5. 계정 또는 하드웨어 지갑 추가:
        private key 선택
        유형 선택:
            JSON 파일
        파일 선택
        비밀번호 입력
    6. 보내기/받기 

현재 보유하고 있는 이더(ETH) 잔액 조회:
    eth.getBalance("0c33043f0926e2e2467fca96117ebefbf86d660b")

이더(ETH) 단위로 변환:
    web3.fromWei(eth.getBalance("d817fee0b5393a005dc639d2abae4896ba38dcd3"), "ether") 

transaction 실습:
    트랜잭션을 보내는 명령어:
        eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(10,"ether")})

    트랜잭션을 확인하는 명령어:
        eth.getTransaction("0xa9fa4c69e819eab15e7973145bc294579c7c0d7328f0491d604b651df2def27c")
        {
            blockHash: "0x5aee0282a3a00ba52f9553de8c1e4945dda82901cb1c1928bab9adabfb041c05", // 블록의 유일한 식별자 역할
            blockNumber: 744, // 블록의 순서
            chainId: "0x3039", // 블록체인 네트워크의 ID
            from: "0x0c33043f0926e2e2467fca96117ebefbf86d660b", // 거래를 발신한 계정(주소)
            gas: 21000, // 거래 수행에 필요한 가스의 양(기본 송금 거래는 21000 가스)
            gasPrice: 1000000000, // 가스 가격(단위: wei)
            hash: "0xa9fa4c69e819eab15e7973145bc294579c7c0d7328f0491d604b651df2def27c", // 이 거래의 고유한 해시값
            input: "0x", // 거래에 포함된 데이터
            nonce: 3, // 발신 계정이 생성된 이후 보낸 거래의 순서 번호
            r: "0x16aa2e2f09e20398ad6e75937e669f9f8f5ea99d99c39db6a2b6d6e6d777c44b", // 디지털 서명의 일부
            s: "0x7385fcba0d5ef180e6b6f23f356011feca2e918656a0f05f613ed887cb0c270e", // 디지털 서명의 일부
            to: "0xd817fee0b5393a005dc639d2abae4896ba38dcd3", // 거래의 수신자 주소
            transactionIndex: 0, // 블록 내에서 이 거래가 몇 번째로 포함되었는지 나타내는 인덱스
            type: "0x0", 거래 유형을 나타내며, 여기서는 일반 거래(legacy transaction)를 의미
            v: "0x6095", // 서명 유효성 검증에 필요
            value: 10000000000000000000 // 송금된 이더(ETH)의 양(단위: wei), 10^19 wei이며, 이는 10 ETH을 의미
        }

    전송되지 않은 트랜잭션을 확인하는 명령어:
        miner.stop()
        eth.mining
        eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(20,"ether")})
        eth.pendingTransactions
        [{
            blockHash: null,
            blockNumber: null,
            chainId: "0x3039",
            from: "0x0c33043f0926e2e2467fca96117ebefbf86d660b",
            gas: 21000,
            gasPrice: 1000000000,
            hash: "0x167cc1b5e9d9cc04bb8cca59e1acb32b6c7e58c6ebd65121f2b0782cf7831c81",
            input: "0x",
            nonce: 4,
            r: "0xaa23f2179c7b1c6fb99e43f02a9c7744069e4fa50a05e4a4d884b5d177e7a128",
            s: "0x170ff701cb41c4e8ba45e719af374acc20ee4ea62a103cfd1e7b5ef117e13e10",
            to: "0xd817fee0b5393a005dc639d2abae4896ba38dcd3",
            transactionIndex: null,
            type: "0x0",
            v: "0x6095",
            value: 10000000000000000000
        }]
        miner.start(1)
        eth.mining
        eth.pendingTransactions

    16진수 데이터를 포함하여 트랜잭션을 보내는 방법:
        eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(20,"ether"), data: "0x01234567"})
        eth.getTransaction("0x3be93044e3b6e25ad7ec4d9352c59038f6ee2437512b6146a2403f81bd12726c")
        {
            blockHash: "0xe71d735029f051512ac949756d9ebb3d00ac6bde8ab251e08da5116040948b57",
            blockNumber: 855,
            chainId: "0x3039",
            from: "0x0c33043f0926e2e2467fca96117ebefbf86d660b",
            gas: 21064,
            gasPrice: 1000000000,
            hash: "0x3be93044e3b6e25ad7ec4d9352c59038f6ee2437512b6146a2403f81bd12726c",
            input: "0x01234567",
            nonce: 5,
            r: "0x4a6087fd613d21cc89da2e0da9684e5f646d3d77b76086bb6d0578993d14b568",
            s: "0x5f931813871ef4d8ed4e75581d2271aadbbd8fa61855ab6457ac79225e2cf485",
            to: "0xd817fee0b5393a005dc639d2abae4896ba38dcd3",
            transactionIndex: 0,
            type: "0x0",
            v: "0x6095",
        value: 20000000000000000000
        }
        https://explorer.popcateum.org/tx/0x9f9cd681bc94325f6252297e9d87e2384739a5984ea033c49645cfc36679be8e?network=Popcateum

    Error: authentication needed: password or unlock 처리:
        1. geth --datadir data --http --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net" --mine --miner.threads "1" --allow-insecure-unlock
        2. pesonal.unlockAccount(eth.accounts[n], "1234', 0)
        3. geth --datadir data --http --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net" --mine --miner.threads "1" --unlock 0 --password password
