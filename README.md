주의 사항:
    1.10.26 버전 기준이며, 상위 버전은 ethash(Ethereum 1.0을 위해 만들어진 PoW 알고리즘)가 작동하지 않는다.

체인 스토리지 초기화: 
    $ geth init --datadir data genesis.json

Geth 실행: 
    $ geth --datadir data --http --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net" (console)

계정 생성: 
    $ geth --datadir data account new 

계정 목록: 
    $ geth --datadir data account list

계정 비밀번호 변경: 
    $ geth --datadir data account update {인덱스}

Geth 콘솔 명령어: 
    $ geth console: 
        Geth 노드를 실행하면서 동시에 JavaScript 콘솔에 접속하는 방법이다.
    $ geth attach http://127.0.0.1:8545:
        이미 실행 중인 Geth 노드에 RPC 서버가 활성화되어 있을 때, 해당 노드에 연결하는 방법이다.

Geth 실행 설정 파일을 지정:
    $ geth --config geth-config.toml

블록체인 데이터 디렉토리를 지정:
    $ geth --datadir data

노드의 동기화 방식을 지정:
    $ geth --syncmode "full": 
        전체 블록체인 데이터를 모두 다운로드하고 검증한다. 가장 안전하지만 시간이 오래 걸린다.
    $ geth --syncmode "snap": 
        전체 블록체인 데이터의 다운로드 대신, 최신 상태의 스냅샷을 다운로드하여 빠르게 노드를 동기화한다.
    $ geth --syncmode "light": 
        경량 노드로, 전체 블록체인 데이터를 저장하지 않고 필요한 정보만 요청하여 동작한다.

Geth에서 가비지 컬렉션(Garbage Collection) 모드 설정:
    $ geth --gcmode "archive": 
        체인 데이터를 완전히 저장하여, 과거의 상태를 조회하거나 분석하는 데 유용하다.

네트워크에 연결하여 Geth 실행:
    $ geth --mainnet
    $ geth --goerli
    $ geth --sepolia

Geth 실행 시, 계정을 잠금/해제:
    $ geth --datadir data --unlock 0 
    $ geth --datadir data --unlock 0 --password password: 
        비밀번호 파일로 잠금 해제
    $ geth --datadir data --unlock 0 --password password --allow-insecure-unlock: 
        계정을 잠금 해제(Unlock) 시 보안 검사를 생략하며, 개발 또는 테스트 환경에서 계정을 잠금 해제 후 채굴 또는 트랜잭션 서명을 허용할 때 사용한다.

HTTP 프로토콜을 통해 노드와 통신:
    $ geth --http: 
        HTTP RPC 서버 활성화
    $ geth --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net":
        API를 활성화
    $ geth --http.corsdomain "*":
        CORS(교차 출처 리소스 공유) 정책을 설정하는 것으로, 모든 도메인(*)에서의 요청을 허용
    $ geth --http.addr "0.0.0.0": 
        HTTP 서버가 모든 네트워크 인터페이스(0.0.0.0)에서 요청을 수신하도록 설정
    $ geth --http.port "8545: 
        HTTP RPC 서버가 사용할 포트 번호를 지정(기본 포트: 8545)

WebSocket 프로토콜을 통해 노드와 통신:
    $ geth --ws
    $ geth --ws.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net"
    $ geth --ws.origins "*"
    $ geth --ws.addr "0.0.0.0"
    $ geth --ws.port "8546

Geth 실행(모든 도메인, 네트워크에서의 요청 및 수신 허용)
    $ geth --datadir data --http --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net" --http.addr "0.0.0.0" --http.corsdomain "*" (console)

블록넘버 확인:
    > eth.blockNumber

마이닝(채굴) 시작/종료:
    > miner.start(1)
    > miner.stop()

블록체인 데이터 내보내기(Geth 종료상태):
    $ geth --datadir data export backup 0 {8}

블록체인 데이터 삭제:
    $ geth --datadir data removedb
    $ eth.blockNumber 로 재확인
    $ geth 폴더 삭제

블록체인 데이터 가져오기(Geth 종료상태):
    $ geth --datadir data import backup

명령어 모음:
    띄어쓰기 두번 + 탭

address:
    이더리움 어드레스는 이더리움 네트워크에서 사용자의 계정을 식별하는 고유한 주소이다.
    보통 42자의 16진수 문자열로 구성되어 있으며, '0x'로 시작한다.
    이 주소를 통해 이더리움 기반의 토큰이나 스마트 계약과의 거래가 이루어지며, 개인의 자산을 안전하게 관리하는 데 중요한 역할을 한다.
    private key > public key > address 순으로 파생되어 생성된다.

address(계좌의 "주소") 생성:
    > personal.newAccount("0000")
    일반적으로 비밀번호를 입력하는 부분은 문자열로 입력해야 하며, 숫자만 넣는 경우 오류가 발생할 수 있다.

keystore(계좌를 안전하게 관리하는 "지갑"):
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
    > eth.coinbase

노드에 저장된 모든 계정 목록:
    > eth.accounts

블록 번호 n번에 해당하는 블록의 정보:
    > eth.getBlock(n)
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
    type Block struct {
        header       *Header // 블록의 헤더 정보
            // 헤더 정보에는 블록의 버전, 이전 블록 해시, 타임스탬프, 난이도, 논스, 거래 루트 등 블록의 핵심 메타데이터가 포함된다.
        uncles       []*Header // 메인 블록과 별개로 유효한 블록 헤더들의 리스트( 블록체인에 보상과 보안 강화를 위해 포함)
        transactions Transactions // 블록에 포함된 거래들의 리스트
        withdrawals  Withdrawals //  출금 관련 데이터

        // witness is not an encoded part of the block body.
        // It is held in Block in order for easy relaying to the places
        // that process it.
        witness *ExecutionWitness // 블록의 실행 증명 또는 검증에 필요한 정보

        // caches
        hash atomic.Pointer[common.Hash] // 블록의 해시값
        size atomic.Uint64 // 블록의 크기

        // These fields are used by package eth to track
        // inter-peer block relay.
        ReceivedAt   time.Time // 블록이 네트워크를 통해 수신된 시간
        ReceivedFrom interface{} // 블록을 전달받은 출처를 나타내는 필드
    }

엉클 블록:
    채굴자가 정식 블록(메인 체인에 포함된 블록)을 채굴하는 것 외에, 경쟁 과정에서 유효하지만 최종 블록으로 채택되지 않은 블록을 의미한다.
    이더리움 1.0 에서는 엉클 블록 채굴자에게도 일정 비율의 보상(75%)이 지급되어, 네트워크의 안정성과 참여를 유도하는 중요한 역할

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
        $ geth --datadir data --http --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net" --mine --miner.threads "1" --unlock 0 --password password --allow-insecure-unlock
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
    > eth.getBalance("0c33043f0926e2e2467fca96117ebefbf86d660b")

이더(ETH) 단위로 변환:
    > web3.fromWei(eth.getBalance("d817fee0b5393a005dc639d2abae4896ba38dcd3"), "ether") 

transaction 실습:
    트랜잭션을 보내는 명령어:
        > eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(10, "ether")})

    트랜잭션을 확인하는 명령어:
        > eth.getTransaction("0xa9fa4c69e819eab15e7973145bc294579c7c0d7328f0491d604b651df2def27c")
        {
            blockHash: "0x5aee0282a3a00ba52f9553de8c1e4945dda82901cb1c1928bab9adabfb041c05", // 블록의 유일한 식별자 역할
            blockNumber: 744, // 블록의 순서
            chainId: "0x3039", // 블록체인 네트워크의 ID
            from: "0x0c33043f0926e2e2467fca96117ebefbf86d660b", // 거래를 발신한 계정(주소)
            gas: 21000, // 거래 수행에 필요한 가스의 양(기본 송금 거래는 21000 가스)
            gasPrice: 1000000000, // 가스 가격(단위: wei), 10^9 wei이며, 이는 1 gwei을 의미
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
        > miner.stop()
        > eth.mining
        > eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(20, "ether")})
        > eth.pendingTransactions
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
        > miner.start(1)
        > eth.mining
        > eth.pendingTransactions

    16진수 데이터를 포함하여 트랜잭션을 보내는 방법:
        > eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(20, "ether"), data: "0x01234567"})
        > eth.getTransaction("0x3be93044e3b6e25ad7ec4d9352c59038f6ee2437512b6146a2403f81bd12726c")
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
        1. $ geth --datadir data --http --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net" --mine --miner.threads "1" --allow-insecure-unlock
        2. $ geth --datadir data --http --http.api "admin, debug, web3, eth, txpool, personal, ethash, miner, net" --mine --miner.threads "1" --unlock 0 --password password
        3. > pesonal.unlockAccount(eth.accounts[n], "1234', 0)

transaction 구조
    geth 코드 - TransactionArgs 구조체 확인:
        go-ethereum\internal\ethapi\transaction_args.go, line: 42
        type TransactionArgs struct {
            From                 *common.Address `json:"from"` // 트랜잭션을 보내는 계정의 주소
            To                   *common.Address `json:"to"` // 트랜잭션이 전달될 대상 계정의 주소
            Gas                  *hexutil.Uint64 `json:"gas"` // 트랜잭션 실행에 사용할 가스 한도
            GasPrice             *hexutil.Big    `json:"gasPrice"` // 가스당 지불할 가격
            MaxFeePerGas         *hexutil.Big    `json:"maxFeePerGas"` // EIP-1559 이후 도입된 최대 가스 요금
            MaxPriorityFeePerGas *hexutil.Big    `json:"maxPriorityFeePerGas"` // 우선순위 수수료로, 채굴자에게 더 빨리 처리되도록 인센티브를 제공하는 금액
            Value                *hexutil.Big    `json:"value"` // 전송할 이더 또는 토큰의 양
            Nonce                *hexutil.Uint64 `json:"nonce"` // 계정의 트랜잭션 순서 번호

            // We accept "data" and "input" for backwards-compatibility reasons.
            // "input" is the newer name and should be preferred by clients.
            // Issue detail: https://github.com/ethereum/go-ethereum/issues/15628
            Data  *hexutil.Bytes `json:"data"` // 트랜잭션에 포함된 데이터
            Input *hexutil.Bytes `json:"input"` // 더 최신 이름이며, 호환성을 위해 둘 다 지원

            // Introduced by AccessListTxType transaction.
            AccessList *types.AccessList `json:"accessList,omitempty"` // EIP-2930에서 도입된 접근 목록으로, 특정 계정 또는 저장소에 대한 접근 권한을 미리 지정하여 가스 비용을 절감할 수 있음
            ChainID    *hexutil.Big      `json:"chainId,omitempty"` // 체인 식별자

            // For BlobTxType
            BlobFeeCap *hexutil.Big  `json:"maxFeePerBlobGas"` // Blob 트랜잭션에서 사용되는 최대 Blob 가스 요금
            BlobHashes []common.Hash `json:"blobVersionedHashes,omitempty"` // Blob 버전의 해시 목록

            // For BlobTxType transactions with blob sidecar
            Blobs       []kzg4844.Blob       `json:"blobs"` // Blob 데이터를 포함하는 필드
            Commitments []kzg4844.Commitment `json:"commitments"` // Blob 관련 커밋먼트 데이터
            Proofs      []kzg4844.Proof      `json:"proofs"` // Blob 관련 증명 데이터

            // For SetCodeTxType
            AuthorizationList []types.SetCodeAuthorization `json:"authorizationList"` // 코드 설정 트랜잭션에서 사용할 승인 목록

            // This configures whether blobs are allowed to be passed.
            blobSidecarAllowed bool // Blob 사이드카를 허용할지 여부를 결정하는 플래그
        }

    geth 코드 - SendTransaction 함수 확인:
        go-ethereum\internal\ethapi\api.go, line: 1485

    geth 코드 - ToTransaction 함수 확인:
        go-ethereum\internal\ethapi\transaction_args.go, line: 471

    geth 코드 - Transaction 구조체 확인:
        go-ethereum\core\types\transaction.go, line: 46
        const (
            LegacyTxType     = 0x00 // 기존 방식의 트랜잭션 타입
            AccessListTxType = 0x01 // EIP-2930에서 도입된 접근 목록(Access List)을 사용하는 트랜잭션 타입
            DynamicFeeTxType = 0x02 // EIP-1559에서 도입된 동적 수수료(가스비) 트랜잭션 타입
            BlobTxType       = 0x03 // 블롭(Blob) 트랜잭션 타입으로, 아직 표준화 또는 특정 용도로 사용될 수 있음
            SetCodeTxType    = 0x04 // 코드 설정(코드 배포 또는 변경)용 트랜잭션 타입
        )

        // Transaction is an Ethereum transaction.
        type Transaction struct {
            inner TxData    // 트랜잭션의 핵심 데이터(컨센서스에 필요한 내용)
            time  time.Time // 트랜잭션이 처음 로컬에서 감지된 시간

            // caches
            hash atomic.Pointer[common.Hash] // 트랜잭션의 해시값을 안전하게 저장
            size atomic.Uint64 // 트랜잭션 크기(바이트 단위)를 저장
            from atomic.Pointer[sigCache] // 송신자 주소 또는 서명 관련 캐시를 저장
        }

    특정 트랜잭션의 원시 데이터 조회:
        해당하는 트랜잭션의 원시 데이터(바이너리 또는 RLP 인코딩된 형식)를 반환
            RLP(Recursive Length Prefix) 인코딩: 이더리움(ethereum) 네트워크에서 주로 트랜잭션, 블록, 계정 상태 등 이더리움의 핵심 데이터를 인코딩하는 데 활용
        eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(10, "ether")})
        eth.getRawTransaction("0xacf4b603260de56b7b57f55f5e3981a7aa607c00b6206dd2062cc6fa958639f9")

    geth 코드 - Receipt(거래 영수증을 나타내는 데이터) 구조체 확인:
        go-ethereum\core\types\receipt.go, line: 52
        type Receipt struct {
            // Consensus fields: These fields are defined by the Yellow Paper
            Type              uint8  `json:"type,omitempty"` // 영수증의 유형을 나타내는 값
            PostState         []byte `json:"root"` // 거래 후 상태 루트 또는 상태 데이터
            Status            uint64 `json:"status"` // 거래의 성공 또는 실패 상태를 나타내는 값
            CumulativeGasUsed uint64 `json:"cumulativeGasUsed" gencodec:"required"` // 해당 블록 내에서 지금까지 사용된 가스 총량
            Bloom             Bloom  `json:"logsBloom"         gencodec:"required"` // 로그 블룸 필터로, 로그 검색에 사용
            Logs              []*Log `json:"logs"              gencodec:"required"` // 거래와 관련된 로그 목록

            // Implementation fields: These fields are added by geth when processing a transaction.
            TxHash            common.Hash    `json:"transactionHash" gencodec:"required"` // 거래의 해시값
            ContractAddress   common.Address `json:"contractAddress"` // 이 거래로 생성된 계약 주소(계약 생성 시에만 유효)
            GasUsed           uint64         `json:"gasUsed" gencodec:"required"` // 해당 거래에 실제로 사용된 가스 양
            EffectiveGasPrice *big.Int       `json:"effectiveGasPrice"` // required, but tag omitted for backwards compatibility // 거래에 적용된 유효 가스 가격
            BlobGasUsed       uint64         `json:"blobGasUsed,omitempty"` // Blob(데이터 블록) 사용 가스량(선택적)
            BlobGasPrice      *big.Int       `json:"blobGasPrice,omitempty"` // Blob에 대한 가스 가격(선택적)

            // Inclusion information: These fields provide information about the inclusion of the
            // transaction corresponding to this receipt.
            BlockHash        common.Hash `json:"blockHash,omitempty"` // 거래가 포함된 블록의 해시값
            BlockNumber      *big.Int    `json:"blockNumber,omitempty"` // 거래가 포함된 블록의 번호
            TransactionIndex uint        `json:"transactionIndex"` // 블록 내에서 거래의 인덱스 위치
        }

    특정 트랜잭션 영수증을 조회:
        eth.getTransactionReceipt("0xacf4b603260de56b7b57f55f5e3981a7aa607c00b6206dd2062cc6fa958639f9")
        {
            blockHash: "0x80effca69dc4dfec4a1045db271bfc6cb7685102d9e2caabf4c42a5918abfc0c",
            blockNumber: 906,
            contractAddress: null,
            cumulativeGasUsed: 21000,
            effectiveGasPrice: 1000000000,
            from: "0x0c33043f0926e2e2467fca96117ebefbf86d660b",
            gasUsed: 21000,
            logs: [],
            logsBloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",      
            status: "0x1",
            to: "0xd817fee0b5393a005dc639d2abae4896ba38dcd3",
            transactionHash: "0xacf4b603260de56b7b57f55f5e3981a7aa607c00b6206dd2062cc6fa958639f9",
            transactionIndex: 0,
            type: "0x0"
        }

signature:
    트랜잭션 서명:
        > eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(10, "ether")})
        > eth.getTransaction("0x9c36184f0c828f62a2f139428b89a1ff7837eaa412d480dc741dadcdd3e9e0b1")
        > eth.signTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(100, "ether"), gas: 21000, gasPrice: 1000000000, nonce: 9})
        {
            raw: "0xf86e09843b9aca0082520894d817fee0b5393a005dc639d2abae4896ba38dcd389056bc75e2d6310000080826095a04db0f3d1503218c516ccb9034b3c3054ceecea4d3aa327981653fcd2d84a84afa0041c841c10a0c04f6091873fd5bdd98f17534bd0a627bb579a163028debe7899",
            tx: {
                gas: "0x5208",
                gasPrice: "0x3b9aca00",
                hash: " ",
                input: "0x",
                maxFeePerGas: null,
                maxPriorityFeePerGas: null,
                nonce: "0x9",
                r: "0x4db0f3d1503218c516ccb9034b3c3054ceecea4d3aa327981653fcd2d84a84af",
                s: "0x41c841c10a0c04f6091873fd5bdd98f17534bd0a627bb579a163028debe7899",
                to: "0xd817fee0b5393a005dc639d2abae4896ba38dcd3",
                type: "0x0",
                v: "0x6095",
                value: "0x56bc75e2d63100000"
            }
        }

    geth 코드 - WithSignature 함수 확인:
        go-ethereum\core\types\transaction_test.go, line: 571

    서명된 트랜잭션 데이터 전송:
        > eth.sendRawTransaction("0xf86e09843b9aca0082520894d817fee0b5393a005dc639d2abae4896ba38dcd389056bc75e2d6310000080826095a04db0f3d1503218c516ccb9034b3c3054ceecea4d3aa327981653fcd2d84a84afa0041c841c10a0c04f6091873fd5bdd98f17534bd0a627bb57
        9a163028debe7899")
        > eth.getTransaction("0x5b867e6b436e8face24f578c118421a5871ffd673a4a9b623e5d518b7c11c598")

Gas:
    사용된 가스 양 확인:
        > eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(100, "ether"), gas: 21000, gasPrice: 1000000000})
        > eth.getTransaction("0xfac9054639e9bb1c71f41058c17c13625640f7e86a88eace39e64b92bc048141")
        > eth.getBlock(1313)
        {
            difficulty: 187573,
            extraData: "0xda83010a1a846765746888676f312e31382e358777696e646f7773",
            gasLimit: 28815225, // 블록 내에서 사용할 수 있는 최대 가스(이더리움 트랜잭션 수수료)의 양
            gasUsed: 21000, // 해당 블록에서 실제로 사용된 가스 양, 여기서는 21000으로, 일반적인 표준 트랜잭션의 가스 소비량
            hash: "0x03ab5bd8c78f8a14ac2d0a8db41a3e46ddc7edb04bb02679954e1d737ae338e4",
            logsBloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            miner: "0x0c33043f0926e2e2467fca96117ebefbf86d660b",
            mixHash: "0xe4cbea6126f9c8ea11b2ca07ccbf98797d8c63cb6bc6274ecf18d6f97a539533",
            nonce: "0x7c0365f248114679",
            number: 1313,
            parentHash: "0x396495cd753738dc6f842d9f0a76b852802f543479c4c8f3c6283124eb1eefe9",
            receiptsRoot: "0x056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
            sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            size: 655,
            stateRoot: "0x1dee9c93797835afb3d6934c1258922fc84bc1fe3882724abdbc4fcb7d2826c2",
            timestamp: 1745722068,
            totalDifficulty: 214471277,
            transactions: ["0xfac9054639e9bb1c71f41058c17c13625640f7e86a88eace39e64b92bc048141"],
            transactionsRoot: "0xd0f214ccc2e12cacb0f0d0b5c4b122946969e86e449590de48ee7b0ef46d8c1c",
            uncles: []
        }

    설정된 최대 한도(1.00 이더)를 초과하는 거래 수수료:
        > eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(100, "ether"), gas: 1000000, gasPrice: 1000000000001})
        geth 코드 - 거래 수수료 최대 한도 확인:
            go-ethereum\internal\ethapi\api.go, line: 1858
            go-ethereum\eth\ethconfig\config.go, line: 71

    일반적인 표준 트랜잭션의 가스(21000) 를 초과하는 경우 반환:
        > eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(100, "ether"), gas: 31000, gasPrice: 1000000000})
        > eth.getTransaction("0x07ffd118c5e8a6914128f452a77bf322f48c4b295c2294bb5a038dc62703e236")
        > eth.getBlock(1567)
        {
            difficulty: 208821,
            extraData: "0xda83010a1a846765746888676f312e31382e358777696e646f7773",
            gasLimit: 30000000,
            gasUsed: 21000, // 일반적인 표준 트랜잭션의 가스(21000)로 반환
            hash: "0xf444db70367e11916246898b6b05ac8120967dcdaba7e2d82b12b92e6b21214a",
            logsBloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            miner: "0x0c33043f0926e2e2467fca96117ebefbf86d660b",
            mixHash: "0xe4c4fee7d40146e07358f787295f635528b5fb01f83be6360bce7d9628afb3a9",
            nonce: "0x2f8d0ac952dc0f49",
            number: 1567,
            parentHash: "0x79555f37bfe7c37b082aecf40ec2a7a4e44e457f331344c55eefb9ce4ebd5454",
            receiptsRoot: "0x056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
            sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            size: 656,
            stateRoot: "0xb38c0f7036e9f2a42f136ab4d318aa0ca6b22b8f4f1109313965677e0a14dc88",
            timestamp: 1745723098,
            totalDifficulty: 264789842,
            transactions: ["0x07ffd118c5e8a6914128f452a77bf322f48c4b295c2294bb5a038dc62703e236"],
            transactionsRoot: "0x192fb95b1cbe304f8ffed350c2cde196a05b2dcc43664332ae2184ba8effc5cb",
            uncles: []
        }

    London Hard Fork:
        기존에는 사용자들이 채굴자에게 직접 수수료를 지불하는 방식이었으나, EIP-1559는 기본 수수료(base fee)를 자동으로 조정하여 거래 수수료의 예측 가능성과 효율성을 높였다.
        또한, 초과 수수료는 소각되어 이더리움의 공급량이 감소하는 효과도 있다.
        genesis.json
        {
            "config": {
                "chainId": 12345,
                "homesteadBlock": 0,
                "eip150Block": 0,
                "eip155Block": 0,
                "eip158Block": 0,
                "byzantiumBlock": 0,
                "constantinopleBlock": 0,
                "petersburgBlock": 0,
                "istanbulBlock": 0,
                "berlinBlock": 0,
                "londonBlock": 0, // London 하드포크 적용 블록 번호
                "ethash": {}
            },
            "difficulty": "1",
            "gasLimit": "8000000",
            "alloc": { // 초기 계좌 잔액 할당 정보
                "d817fee0b5393a005dc639d2abae4896ba38dcd3": { "balance": "1000000000" }
            }
        }

    baseFeePerGas 확인:
        > eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(10, "ether"), gas: 21000, gasPrice: 1000000000})
        > eth.getTransaction("0xb0a305e907c6fdf7e01323f847787e937e8b70ca8ffbaa5073f77a1c3cffff7c")
        > eth.getBlock(57)
        {
            baseFeePerGas: 494837, // 거래를 처리하는 데 필요한 기본 가스 비용
            difficulty: 134615,
            extraData: "0xda83010a1a846765746888676f312e31382e358777696e646f7773",
            gasLimit: 8457626,
            gasUsed: 21000,
            hash: "0xe270566d5db15874908b9488f5e10c8df63546e416e189433452b803675bac31",
            logsBloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            miner: "0x0c33043f0926e2e2467fca96117ebefbf86d660b",
            mixHash: "0x951f9430b56e1539abf3576d275c13c808a6fd1d1b634cd28c7007bbf8332494",
            nonce: "0x6fa63d153c219923",
            number: 57,
            parentHash: "0x7c66dd568d9e89fd389a349ac76d491350cf368bf70730edbd9c9a8f32cb5da5",
            receiptsRoot: "0x056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
            sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            size: 656,
            stateRoot: "0x60c9f241f1c02133ae133f65a69d06c0af42ab04dea91d449bcd9174e7ffec89",
            timestamp: 1745724590,
            totalDifficulty: 7571477,
            transactions: ["0xb0a305e907c6fdf7e01323f847787e937e8b70ca8ffbaa5073f77a1c3cffff7c"],
            transactionsRoot: "0x11d7af1070f43b6bf507309379737972c276733b5afc7e8c65917ef3913223a9",
            uncles: []
        }

        geth 코드 - CalcBaseFee 함수 확인:
            go-ethereum\consensus\misc\eip1559\eip1559.go, line: 56
        
        geth 코드 - DynamicFeeTx 구조체 확인:
            go-ethereum\core\types\tx_dynamic_fee.go, line: 28
            type DynamicFeeTx struct {
                ChainID    *big.Int
                Nonce      uint64
                GasTipCap  *big.Int // a.k.a. maxPriorityFeePerGas, 채굴자에게 지급하는 수수료
                GasFeeCap  *big.Int // a.k.a. maxFeePerGas, 최대 전체 수수료(가스비 한도), 거래를 성공적으로        처리하려면 maxFeePerGas 는 적어도 baseFee 보다 높거나 같아야 한다.
                Gas        uint64
                To         *common.Address `rlp:"nil"` // nil means contract creation
                Value      *big.Int
                Data       []byte
                AccessList AccessList

                // Signature values
                V *big.Int
                R *big.Int
                S *big.Int
            }
            
        Total Gas Fee(총 가스 수수료):
            (baseFee + maxPriorityFeePerGas) * gasUsed
            > eth.sendTransaction({from: eth.accounts[0], to: eth.accounts[1], value: web3.toWei(10, "ether"), maxFeePerGasmax: 1000000000, maxPriorityFeePerGas: 1000000000})
            > eth.getTransaction("0x0a14f9a3e543658c3de30b4a3eb47b8fa8472f1fa8ae10e8814a15dcc26dd71a")
            > eth.getBlock(324)
            {
                baseFeePerGas: 7,
                difficulty: 152397,
                extraData: "0xda83010a1a846765746888676f312e31382e358777696e646f7773",
                gasLimit: 10975235,
                gasUsed: 21000,
                hash: "0x0884d55f9b1c6d2faa4616e7dbaf26d849cafc7365b6ab9721358806b57001f3",
                logsBloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                miner: "0x0c33043f0926e2e2467fca96117ebefbf86d660b",
                mixHash: "0xc43d335252207433951f0c0c909f2dc3ca867c4e9705171fd98b78239ebc7112",
                nonce: "0x16c081d87f678c67",
                number: 324,
                parentHash: "0xc6af7a8f2b46d93c51992dd815422ec23f031dd7e015d49f42ca25a38008b56b",
                receiptsRoot: "0xf78dfb743fbd92ade140711c8bbc542b5e307f0ab7984eff35d751969fe57efa",
                sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                size: 665,
                stateRoot: "0x34f1294bdbfa37e639fc16e446fbb6dad183892751816ade1031f89023ac5273",
                timestamp: 1745725364,
                totalDifficulty: 45839255,
                transactions: ["0x0a14f9a3e543658c3de30b4a3eb47b8fa8472f1fa8ae10e8814a15dcc26dd71a"],
                transactionsRoot: "0x90b396e3f184e1054f71f2814fad5df9e93e7bab4dc2f18ce888b8ab8ec57731",
                uncles: []
            }

        Total Gas Fee = (baseFee + maxPriorityFeePerGas) * gasUsed
            baseFeePerGas = 7 (이 값은 가스 단위가 wei가 아니기 때문에, 실제 계산 시 wei 단위로 변환 필요)
            maxPriorityFeePerGas = 1,000,000,000 wei
            gasUsed = 21,000
            Total Gas Fee = 1,000,000,007 * 21,000 wei
            즉, 약 21,000,000,147,000 wei 가 된다.
            
            이더(ETH) 로 환산 시, 21,000,000,147,000 wei ÷ 10^18
            21,000,000,147,000 ÷ 1,000,000,000,000,000,000 = 0.000021 이더로 표현된다.

solidity 컨트랙트 배포:
    Solidity 공식 문서:
        https://docs.soliditylang.org/en/v0.8.17/introduction-to-smart-contracts.html#a-simple-smart-contract
        
    Remix IDE (Solidity IDE):
        Remix IDE 설치:
            https://remix.ethereum.org/#lang=en&optimize=false&runs=200&evmVersion=null&version=soljson-v0.8.7+commit.e28d00a7.js
    
        storage.sol 파일 생성:
            // SPDX-License-Identifier: GPL-3.0
            pragma solidity >=0.4.16 <0.9.0;

            contract SimpleStorage {
                uint storedData;

                function set(uint x) public {
                    storedData = x;
                }

                function get() public view returns (uint) {
                    return storedData;
                }
            }

        solidity compiler:
            complier > 0.8.7+commit.e28d00a7    
    
        solidity contract 배포:
            metamask 동기화:
                Remix IDE > injected Provier - MetaMask

            solidity contract 배포, 트랜잭션의 영수증 조회: 
                depoly
                metamask > 계약 배포 > 트랜잭션 ID 복사
                > eth.getTransaction("0x0e963660c27424830b64ba1d23ac977aada6b6dc26fa7d13198f671262c4d691")
                > eth.getTransactionReceipt("0x0e963660c27424830b64ba1d23ac977aada6b6dc26fa7d13198f671262c4d691")
                {
                    blockHash: "0xd3357635470b3c618fb4779eba7c62fafbcb1125e15b4e4c6ddfdf7e59e8c0e5",
                    blockNumber: 877,
                    contractAddress: "0x37d0b67cc1fc7e71efc6cb4560ed4992a2705d98", // 컨트랙트 주소, Remix IDE의 Deployed Contracts 와 동일한 값
                    cumulativeGasUsed: 125677, // 누적 가스 사용량
                    effectiveGasPrice: 1000000007, // 실제 가스 가격
                    from: "0x0c33043f0926e2e2467fca96117ebefbf86d660b",
                    gasUsed: 125677, // 실제로 소모된 가스
                    logs: [],
                    logsBloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    status: "0x1",
                    to: null,
                    transactionHash: "0x0e963660c27424830b64ba1d23ac977aada6b6dc26fa7d13198f671262c4d691",
                    transactionIndex: 0,
                    type: "0x2"
                }

        function selector 사용:
            Remix IDE > Set: 1
            > eth.getTransaction("0x7db828ec2fd80121f0cd08a0d8c1221b42295acd2e66552640ea7fb6edd50982")
            {
                accessList: [],
                blockHash: "0x094bd5ccc71ec47b0e7aead795a2bdbd91df436361c99c973c6508be00e3a061",
                blockNumber: 992,
                chainId: "0x3039",
                from: "0x0c33043f0926e2e2467fca96117ebefbf86d660b", // 거래를 발신한 계정(주소)
                gas: 26602,
                gasPrice: 1000000007,
                hash: "0x7db828ec2fd80121f0cd08a0d8c1221b42295acd2e66552640ea7fb6edd50982",
                input: "0x60fe47b10000000000000000000000000000000000000000000000000000000000000001",
                maxFeePerGas: 1000000007,
                maxPriorityFeePerGas: 1000000007,
                nonce: 9,
                r: "0x1341c9a71f7f2a9a3b572f8ff092732c957f2ca6fb2200f2d961b9474a355f1c",
                s: "0x5a6d94fccd187e614bbc51c98623d496f5af0e6fff3aa093813a5fbafa07de8b",
                to: "0x37d0b67cc1fc7e71efc6cb4560ed4992a2705d98", // 컨트랙트 주소
                transactionIndex: 0,
                type: "0x2",
                v: "0x1",
                value: 0
            }

        geth 에서 function selector 사용:
            > eth.sendTransaction({from: eth.accounts[0], to: "0x37d0b67cc1fc7e71efc6cb4560ed4992a2705d98", data: "0x60fe47b10000000000000000000000000000000000000000000000000000000000000009"})

    solcjs (Solidity 컴파일러):
        solcjs 설치:
            $ npm install -g solc@0.8.17

        storage.sol 파일 생성:
            // SPDX-License-Identifier: GPL-3.0
            pragma solidity >=0.4.16 <0.9.0;

            contract SimpleStorage {
                uint storedData;

                function set(uint x) public {
                    storedData = x;
                }

                function get() public view returns (uint) {
                    return storedData;
                }
            }

        solidity contract 배포:
            solidity contract 컴파일:
                $ solcjs --bin --abi ./storage.sol

            storage_sol_SimpleStorage.abi:
                스마트 계약의 인터페이스를 정의하는 JSON 형식의 데이터

            storage_sol_SimpleStorage.bin:
                컴파일된 스마트 계약의 바이트코드(바이너리 코드)

            $ geth attach "http://127.0.0.1:8545"

            > let storageAbi = {storage_sol_SimpleStorage.abi}
            > storageAbi

            storage_sol_SimpleStorage.bin 16진수 표기 필수:
                > let storageBin = "{'0x'storage_sol_SimpleStorage..bin}"
            > storageBin

            > let storageContract = eth.contract(storageAbi)
            > storageContract
            {
                abi: [{
                    inputs: [],
                    name: "get",
                    outputs: [{...}],
                    stateMutability: "view",
                    type: "function"
                }, {
                    inputs: [{...}],
                    name: "set",
                    outputs: [],
                    stateMutability: "nonpayable",
                    type: "function"
                }],
                address: undefined,
                transactionHash: "0x79745b97b5ccfa12f4fb0ed3a8531fa3ba9e3e36073753fa20c586fe972d0f01"
            }
            > eth.getTransactionReceipt("0x79745b97b5ccfa12f4fb0ed3a8531fa3ba9e3e36073753fa20c586fe972d0f01")
            {
                blockHash: "0x2c52e13890c49bc49c6373e7f0cf62b15456c2acfd9e76d2a243b39cd8825af6",
                blockNumber: 2048,
                contractAddress: "0xd28e16f8e079d64e32a50e35f90bf11f40be4deb",
                cumulativeGasUsed: 125653,
                effectiveGasPrice: 1000000007,
                from: "0x0c33043f0926e2e2467fca96117ebefbf86d660b",
                gasUsed: 125653,
                logs: [],
                logsBloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                status: "0x1",
                to: null,
                transactionHash: "0x79745b97b5ccfa12f4fb0ed3a8531fa3ba9e3e36073753fa20c586fe972d0f01",
                transactionIndex: 0,
                type: "0x2"
            }

        Remix IDE 에서 contract 사용:
            Load contract from Address: 0xd28e16f8e079d64e32a50e35f90bf11f40be4deb > At Address > Set
            > eth.getTransaction("0x04500564ec8ac31769685c9454b745924e14602de7ba12ae815811610c635c27")
            {
                accessList: [],
                blockHash: "0xa9f3cbab7ca47ecaa79b07fb649a8cdad53492063455c13653ef97c4dcb47a8b",
                blockNumber: 2119,
                chainId: "0x3039",
                from: "0x0c33043f0926e2e2467fca96117ebefbf86d660b",
                gas: 26602,
                gasPrice: 1000000007,
                hash: "0x04500564ec8ac31769685c9454b745924e14602de7ba12ae815811610c635c27",
                input: "0x60fe47b10000000000000000000000000000000000000000000000000000000000000004",
                maxFeePerGas: 1000000007,
                maxPriorityFeePerGas: 1000000007,
                nonce: 21,
                r: "0xb2c732d489a0a363c99d8fc8c0613e681fa7341545f82b71bff238017802cd8e",
                s: "0x2bd0dbe4b5d434eb4c7aafbaee535de0b77bccc8ec0d9dc107563b46d4c4542e",
                to: "0xd28e16f8e079d64e32a50e35f90bf11f40be4deb",
                transactionIndex: 0,
                type: "0x2",
                v: "0x0",
                value: 0
            }
            
evm 과 opcode:
    EVM(Ethereum Virtual Machine):
        이더리움 네트워크 내에서 스마트 계약을 실행하고 분산 애플리케이션을 구동하는 가상화된 컴퓨팅 환경
        
        geth 코드 - Evm version 확인:
            go-ethereum\core\vm\interpreter.go, line: 105

    opcode(operation code):
        EVM 이 이해하고 실행할 수 있는 저수준의 명령어 집합

        geth 코드 - opcode 확인:
            go-ethereum\core\vm\opcodes.go, line: 34

        opcode 테이블:
            https://github.com/crytic/evm-opcodes

        트랜잭션의 내부 실행 과정을 단계별로 추적하여 디버깅:
            > debug.traceTransaction("0xc0f2056d868645fe7e80afc0d6097b8997236ac8731a866cb15e6537a8bb78f8")
            {
                failed: false,
                gas: 125677,
                returnValue: "608060405234801561001057600080fd5b50600436106100365760003560e01c806360fe47b11461003b5780636d4ce63c14610057575b600080fd5b6100556004803603810190610050919061009d565b610075565b005b61005f61007f565b60405161006c91906100d9565b60405180910390f35b8060008190555050565b60008054905090565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea2646970667358221220422e225cd4efcb12ae372d7d760fa3d9ccebc8c2f724d69b2bc58cd7193c7cc064736f6c63430008070033",
                structLogs: [{
                    depth: 1,
                    gas: 67317,
                    gasCost: 3,
                    op: "PUSH1", // 0x60
                    pc: 0,
                    stack: []
                }, {
                    depth: 1,
                    gas: 67314,
                    gasCost: 3,
                    op: "PUSH1", // 0x60
                    pc: 2,
                    stack: ["0x80"]
                }, {
                    depth: 1,
                    gas: 67311,
                    gasCost: 12,
                    op: "MSTORE", // 0x52
                    pc: 4,
                    stack: ["0x80", "0x40"]
                }, {
                    depth: 1,
                    gas: 67299,
                    gasCost: 2,
                    op: "CALLVALUE",
                    pc: 5,
                    stack: []
                }, {
                    depth: 1,
                    gas: 67297,
                    gasCost: 3,
                    op: "DUP1",
                    pc: 6,
                    stack: ["0x0"]
                }, 
                .
                .
                .
                {
                    depth: 1,
                    gas: 67200,
                    gasCost: 0,
                    op: "RETURN",
                    pc: 30,
                    stack: ["0x150", "0x0"]
                }]
            }

merkle tree:
    머클 트리는 여러 개의 데이터를 계층적으로 연결하여, 전체 데이터의 무결성을 빠르고 효율적으로 검증할 수 있도록 하는 이진 트리 구조이다.
    
    구조와 작동 원리:
        루트 노드(Root Node):
            모든 하위 노드의 해시값이 결합되어 최상단에 위치하며, 전체 데이터 집합의 대표값이며,
            이 해시값을 통해 전체 데이터의 무결성을 검증할 수 있다.
        내부 노드(Non-Leaf Nodes): 
            자식 노드들의 해시값을 결합(이진 트리)하여 새로운 해시값을 계산한다.
        리프 노드(Leaf Nodes): 
            원본 데이터 또는 데이터 조각의 해시값이 저장된다.

    작동 과정 예시:
        여러 개의 데이터 조각이 있다고 가정: D1, D2, D3, D4
        각 데이터의 해시값을 계산: H(D1), H(D2), H(D3), H(D4)
        인접한 해시값을 결합하여 새로운 해시값 계산:
        H12 = 해시(H(D1) + H(D2))
        H34 = 해시(H(D3) + H(D4))
        마지막으로, 이 두 해시값을 결합하여 루트 해시값을 계산:
        H1234 = 해시(H12 + H34)
        이 H1234가 바로 전체 데이터 집합의 무결성을 대표하는 루트 해시값이다.

patricia trie:
    패트리샤 트라이는 기본적인 트라이(Trie) 구조에 압축(compression) 기법을 적용한 데이터 구조이다.
    
    구조와 작동 원리:
        내부 노드(Non-Leaf Nodes):
            공통 접두사를 나타내며, 자식 노드로 분기한다.
        리프 노드(Leaf Nodes):
            최종 키 값 또는 관련 데이터를 저장한다.

    작동 과정 예시:
        검색: 키의 공통 접두사를 따라 내려가며, 일치하는 경로를 찾는다.
        삽입: 새 키의 공통 접두사를 계산하고, 적절한 위치에 노드를 생성하거나 병합한다.
        삭제: 해당 키를 찾은 후, 필요에 따라 노드를 제거하거나 병합하여 구조를 최적화한다.
        예를 들어, IP 주소 192.168.0.1과 192.168.0.2는 공통 접두사 '192.168.0'을 공유하며, 이를 하나의 노드로 압축할 수 있다.

merkle patricia tree:
    블록체인 기술에서 데이터의 무결성과 효율적인 검증을 위해 사용되는 Merkle Tree와 Patricia Trie(혹은 Radix Tree)의 특징을 결합한 데이터 구조이다.
    
levelDB:
    이더리움에서 블록체인 데이터를 저장하는 데 사용되는 기본 데이터베이스이며, 이더리움 노드가 블록체인 상태, 트랜잭션 기록, 계정정보 등을 효율적으로 저장하고 빠르게 접근할 수 있도록 도와준다.

    geth 코드 - levelDB 확인:
        go-ethereum\core\rawdb\schema.go, line: 30

    goleveldb 모듈:
        Go 프로그래밍 언어로 LevelDB 키/값 데이터베이스를 구현한 것이다.

        설치:
            $ go mod init geth
            $ go get github.com/syndtr/goleveldb/leveld

        사용(Geth 종료상태):
            > eth.blockNumber
            > eth.getBlock(2679)
            {
                baseFeePerGas: 7,
                difficulty: 337101,
                extraData: "0xda83010a1a846765746888676f312e31382e358777696e646f7773",
                gasLimit: 30000000,
                gasUsed: 0,
                hash: "0xa879438763c34a9c7b53f6fc0cb79b67e789b23e0a89218f8ee60ed88d9e3699",
                logsBloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                miner: "0x0c33043f0926e2e2467fca96117ebefbf86d660b",   
                mixHash: "0x9394b10e08f263f196ed4261dc607c3856ab368f78183c6bb2e9925ecba18ad2",
                nonce: "0x414e3b8260bab7aa",
                number: 2679,
                parentHash: "0x00f0d16d1ae0fd6a29928c6c3ed7fb09105a6571c37d1e3b5645169534456266",
                receiptsRoot: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                size: 542,
                stateRoot: "0xd2266c557d0b30ff11ac670f86da87aed75306082be47a0b426447b84e04d559",
                timestamp: 1745904570,
                totalDifficulty: 619355398,
                transactions: [],
                transactionsRoot: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                uncles: []
            }

            $ cd levelDB/
            $ go run main.go
            [168 121 67 135 99 195 74 156 123 83 246 252 12 183 155 103 231 137 178 62 10 137 33 143 142 230 14 216 141 158 54 153]
            Encoded Hex String:  a879438763c34a9c7b53f6fc0cb79b67e789b23e0a89218f8ee60ed88d9e3699

    geth-leveldb-explorer (GO에서 Geth를 위한 데이터베이스 탐색기):
        https://github.com/MartiTM/geth-leveldb-explorer
