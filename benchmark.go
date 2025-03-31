package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"log"
	"runtime"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20"
)

func main() {

	// print platform information
	fmt.Printf("Platform: %s\n", runtime.GOOS)
	fmt.Printf("Architecture: %s\n", runtime.GOARCH)
	fmt.Printf("Number of CPU cores: %d\n", runtime.NumCPU())
	fmt.Printf("Memory Allocated: %d KB\n", runtime.NumGoroutine()*1024)
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Print("Log format: NAME, TIME, MEMORY, CPU, RESULT_SIZE\n")

	// 128 KB, 256 KB, 512 KB, 1 MB, 5 MB
	dataSizes := []int{128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024, 5 * 1024 * 1024}
	for _, dataSize := range dataSizes {
		fmt.Printf("\n\nData Size: %d KB\n", dataSize/1024)

		// Генерація випадкових даних
		data := make([]byte, dataSize)
		_, err := rand.Read(data)
		if err != nil {
			log.Fatalf("Error generating random data: %v", err)
		}

		aesBenchmark(data)
		rsaBenchmark(data)
		sha256Benchmark(data)
		sha512Benchmark(data)
		bcryptBenchmark(data)
		chacha20Benchmark(data)
		tripleDESBenchmark(data)
		hmacBenchmark(data)
		eccBenchmark(data)
	}
}

func logBenchmarkResult(algorithmName string, elapsedTime time.Duration, memoryUsage uint64, cpuUsage int, resultSize int) {
	fmt.Printf(
		"\n%s | %v | %v KB | %d cores | %d KB",
		algorithmName, elapsedTime, memoryUsage/1024, cpuUsage, resultSize/1024,
	)
}

func aesBenchmark(data []byte) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Error generating AES key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating AES cipher: %v", err)
	}

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		log.Fatalf("Error generating IV: %v", err)
	}

	startTime := time.Now()
	ciphertext := make([]byte, len(data))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, data)
	elapsedTime := time.Since(startTime)

	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	cpuUsage := runtime.NumCPU()

	logBenchmarkResult("AES", elapsedTime, memStats.TotalAlloc, cpuUsage, len(ciphertext))
}

func rsaBenchmark(data []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key: %v", err)
	}

	maxChunkSize := privateKey.PublicKey.Size() - 11 // 11 bytes for PKCS#1 v1.5 padding
	chunks := len(data) / maxChunkSize
	if len(data)%maxChunkSize != 0 {
		chunks++
	}

	startTime := time.Now()
	var ciphertext []byte
	for i := 0; i < chunks; i++ {
		start := i * maxChunkSize
		end := start + maxChunkSize
		if end > len(data) {
			end = len(data)
		}

		chunkCiphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, data[start:end])
		if err != nil {
			log.Fatalf("Error encrypting with RSA: %v", err)
		}
		ciphertext = append(ciphertext, chunkCiphertext...)
	}
	elapsedTime := time.Since(startTime)

	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	cpuUsage := runtime.NumCPU()

	logBenchmarkResult("RSA", elapsedTime, memStats.TotalAlloc, cpuUsage, len(ciphertext))
}

func sha256Benchmark(data []byte) {
	startTime := time.Now()
	hash := sha256.Sum256(data)
	elapsedTime := time.Since(startTime)

	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	cpuUsage := runtime.NumCPU()

	logBenchmarkResult("SHA-256", elapsedTime, memStats.TotalAlloc, cpuUsage, len(hash))
}

func sha512Benchmark(data []byte) {
	startTime := time.Now()
	hash := sha512.Sum512(data)
	elapsedTime := time.Since(startTime)

	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	cpuUsage := runtime.NumCPU()

	logBenchmarkResult("SHA-512", elapsedTime, memStats.TotalAlloc, cpuUsage, len(hash))
}

func bcryptBenchmark(data []byte) {
	if len(data) > 72 {
		data = data[:72]
	}

	startTime := time.Now()
	hashedPassword, err := bcrypt.GenerateFromPassword(data, bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Error hashing password with bcrypt: %v", err)
	}
	elapsedTime := time.Since(startTime)

	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	cpuUsage := runtime.NumCPU()

	logBenchmarkResult("bcrypt", elapsedTime, memStats.TotalAlloc, cpuUsage, len(hashedPassword))
}

func chacha20Benchmark(data []byte) {
	key := make([]byte, chacha20.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Error generating ChaCha20 key: %v", err)
	}

	nonce := make([]byte, chacha20.NonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatalf("Error generating ChaCha20 nonce: %v", err)
	}

	startTime := time.Now()
	ciphertext := make([]byte, len(data))
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		log.Fatalf("Error creating ChaCha20 cipher: %v", err)
	}
	stream.XORKeyStream(ciphertext, data)
	elapsedTime := time.Since(startTime)

	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	cpuUsage := runtime.NumCPU()

	logBenchmarkResult("ChaCha20", elapsedTime, memStats.TotalAlloc, cpuUsage, len(ciphertext))
}

func tripleDESBenchmark(data []byte) {
	key := make([]byte, 24) // 3DES requires a 24-byte key
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Error generating 3DES key: %v", err)
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		log.Fatalf("Error creating 3DES cipher: %v", err)
	}

	iv := make([]byte, des.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		log.Fatalf("Error generating IV: %v", err)
	}

	startTime := time.Now()
	ciphertext := make([]byte, len(data))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, data)
	elapsedTime := time.Since(startTime)

	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	cpuUsage := runtime.NumCPU()

	logBenchmarkResult("3DES", elapsedTime, memStats.TotalAlloc, cpuUsage, len(ciphertext))
}

func hmacBenchmark(data []byte) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Error generating HMAC key: %v", err)
	}

	startTime := time.Now()
	h := hmac.New(sha256.New, key)
	h.Write(data)
	mac := h.Sum(nil)
	elapsedTime := time.Since(startTime)

	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	cpuUsage := runtime.NumCPU()

	logBenchmarkResult("HMAC", elapsedTime, memStats.TotalAlloc, cpuUsage, len(mac))
}

func eccBenchmark(data []byte) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Error generating ECC key: %v", err)
	}

	hash := sha256.Sum256(data)

	startTime := time.Now()
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		log.Fatalf("Error signing with ECC: %v", err)
	}
	elapsedTime := time.Since(startTime)

	startVerifyTime := time.Now()
	valid := ecdsa.Verify(&privateKey.PublicKey, hash[:], r, s)
	verifyElapsedTime := time.Since(startVerifyTime)

	if !valid {
		log.Fatalf("ECC signature verification failed")
	}

	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	cpuUsage := runtime.NumCPU()

	logBenchmarkResult("ECC Signing", elapsedTime, memStats.TotalAlloc, cpuUsage, len(r.Bytes())+len(s.Bytes()))

	logBenchmarkResult("ECC Verification", verifyElapsedTime, memStats.TotalAlloc, cpuUsage, 0)
}
