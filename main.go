package main

import "fmt"

type Trie struct {
	children  map[rune]*Trie
	endOfWord bool
}

func (t *Trie) Insert(word string) {
	fmt.Printf("%p \n", t)
	for _, r := range word {
		// 아스키 코드:
		// 	https://gist.github.com/codebrainz/3883648
		if t.children[r] == nil {
			t.children[r] = &Trie{children: make(map[rune]*Trie)}
		}
		/*
			포인터 재할당의 영향 범위:
				메서드 내에서 포인터를 '재할당' 하면,
				이 변경은 해당 메서드 내부의 변수에만 적용된다.
				메서드가 종료되면, 이 변경은 호출한 쪽의 포인터 변수에는 영향을 미치지 않는다.
		*/
		t = t.children[r]
	}
	t.endOfWord = true
}

func (t *Trie) Search(word string) bool {
	for _, r := range word {
		if t.children[r] == nil {
			return false
		}
		t = t.children[r]
	}
	return t.endOfWord
}

func main() {
	t := &Trie{children: make(map[rune]*Trie)}
	t.Insert("hello")
	fmt.Printf("%p \n", t)
	fmt.Println(t.Search("hello"))
}
