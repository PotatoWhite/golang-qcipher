package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"github.com/cloudflare/circl/pke/kyber/kyber1024"
)

// 암호화할 메시지: 애국가 전체 텍스트
var target = []byte(`1. 동해물과 백두산이 마르고 닳도록...`)

// 블록 단위로 32바이트씩 나눠주는 함수 (Kyber 제약에 맞춤)
func splitIntoKyberBlocks(data []byte) [][]byte {
	var blocks [][]byte
	for i := 0; i < len(data); i += 32 { // 32바이트씩 나눔
		end := i + 32
		block := make([]byte, 32) // 항상 32바이트 크기로 초기화
		if end > len(data) {
			copy(block, data[i:]) // 남은 데이터가 32바이트 미만이면 패딩 추가
		} else {
			copy(block, data[i:end]) // 32바이트로 정확히 복사
		}
		blocks = append(blocks, block)
	}
	return blocks
}

// RSA1024 성능 측정 함수
func benchmarkRSA1024() {
	fmt.Println("\n[RSA1024 성능 측정]")
	priv, _ := rsa.GenerateKey(rand.Reader, 1024) // RSA 1024비트 키 생성
	pub := &priv.PublicKey                        // 공개 키 추출

	// 메시지를 32바이트 블록으로 분할
	blocks := splitIntoKyberBlocks(target)
	var encrypted [][]byte

	// RSA 암호화 시작
	start := time.Now()
	for _, block := range blocks {
		encBlock, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, block, nil)
		if err != nil {
			log.Fatalf("RSA 암호화 실패: %v", err)
		}
		encrypted = append(encrypted, encBlock) // 암호화된 블록 저장
	}
	fmt.Printf("RSA 암호화 시간: %s\n", time.Since(start))

	// RSA 복호화 시작
	var decrypted []byte
	start = time.Now()
	for _, encBlock := range encrypted {
		decBlock, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encBlock, nil)
		if err != nil {
			log.Fatalf("RSA 복호화 실패: %v", err)
		}
		decrypted = append(decrypted, decBlock...) // 복호화된 블록 결합
	}
	fmt.Printf("RSA 복호화 시간: %s\n", time.Since(start))
	fmt.Printf("복호화된 메시지: %s\n", string(decrypted))
}

// Kyber1024 성능 측정 함수
func benchmarkKyber1024() {
	fmt.Println("\n[Kyber1024 성능 측정]")
	pubKey, secKey, _ := kyber1024.GenerateKey(nil) // Kyber1024 키 생성

	// 메시지를 32바이트 블록으로 분할
	blocks := splitIntoKyberBlocks(target)
	var encrypted [][]byte

	// Kyber1024 암호화 시작
	start := time.Now()
	for _, block := range blocks {
		ciphertext := make([]byte, kyber1024.CiphertextSize) // 암호문 공간 확보
		seed := make([]byte, kyber1024.EncryptionSeedSize)   // 난수 시드 생성
		rand.Read(seed)

		pubKey.EncryptTo(ciphertext, block, seed) // 암호화 수행
		encrypted = append(encrypted, ciphertext) // 암호화된 블록 저장
	}
	fmt.Printf("Kyber1024 암호화 시간: %s\n", time.Since(start))

	// Kyber1024 복호화 시작
	var decrypted []byte
	start = time.Now()
	for _, ciphertext := range encrypted {
		decBlock := make([]byte, kyber1024.PlaintextSize) // 복호화된 평문 저장소
		secKey.DecryptTo(decBlock, ciphertext)            // 복호화 수행
		decrypted = append(decrypted, decBlock...)        // 복호화된 블록 결합
	}
	fmt.Printf("Kyber1024 복호화 시간: %s\n", time.Since(start))
	fmt.Printf("복호화된 메시지: %s\n", string(decrypted))
}

// 메인 함수: 성능 측정 함수 실행
func main() {
	benchmarkRSA1024()   // RSA1024 성능 측정
	benchmarkKyber1024() // Kyber1024 성능 측정
}
