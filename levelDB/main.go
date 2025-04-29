package main

import (
	"encoding/hex"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
)

func main() {
	db, err := leveldb.OpenFile("../data/geth/chaindata", nil) // 지정된 경로에 있는 LevelDB 데이터베이스를 열기
	if err != nil {
		fmt.Println("Error opening LevelDB: ", err)
		return
	}
	defer db.Close()

	dbKey := []byte("LastBlock")    // "LastBlock" 이라는 키를 바이트 슬라이스로 정의
	data, err := db.Get(dbKey, nil) // 해당 키에 저장된 데이터를 읽어옴
	if err != nil {
		fmt.Println("Error reading from LevelDB: ", err)
		return
	}

	encodedString := hex.EncodeToString(data) // 바이트 배열을 헥사 문자열로 인코딩
	fmt.Println(data)
	fmt.Println("Encoded Hex String: ", encodedString)
}
