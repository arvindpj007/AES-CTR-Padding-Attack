package main

import (
	"crypto/aes"
	"crypto/rand"
	"flag"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strconv"
)

//A binary to hexadecimal map
var binHexMap = make(map[string]string)

//A hexadecimal to binary map
var hexBinMap = make(map[string]string)

//A 16 byte constant wiyh hexadecimal value 1
const hexOne16 = "00000000000000000000000000000001"

//Function to setup and initialize the binary to hexadecimal mapping
func setupBinHexMap() {

	binHexMap["0000"] = "0"
	binHexMap["0001"] = "1"
	binHexMap["0010"] = "2"
	binHexMap["0011"] = "3"
	binHexMap["0100"] = "4"
	binHexMap["0101"] = "5"
	binHexMap["0110"] = "6"
	binHexMap["0111"] = "7"
	binHexMap["1000"] = "8"
	binHexMap["1001"] = "9"
	binHexMap["1010"] = "a"
	binHexMap["1011"] = "b"
	binHexMap["1100"] = "c"
	binHexMap["1101"] = "d"
	binHexMap["1110"] = "e"
	binHexMap["1111"] = "f"
}

//Function to setup and initialize the hexadecimal to binary mapping
func setupHexBinMap() {

	hexBinMap["0"] = "0000"
	hexBinMap["2"] = "0010"
	hexBinMap["1"] = "0001"
	hexBinMap["3"] = "0011"
	hexBinMap["4"] = "0100"
	hexBinMap["5"] = "0101"
	hexBinMap["6"] = "0110"
	hexBinMap["7"] = "0111"
	hexBinMap["8"] = "1000"
	hexBinMap["9"] = "1001"
	hexBinMap["a"] = "1010"
	hexBinMap["b"] = "1011"
	hexBinMap["c"] = "1100"
	hexBinMap["d"] = "1101"
	hexBinMap["e"] = "1110"
	hexBinMap["f"] = "1111"
}

//Funciton to throw an error when the input CLI has missing/wrong parameters
func missingParametersError() {

	fmt.Println("ERROR: Parameters missing!")
	fmt.Println("HELP:")
	fmt.Println("encrypt-auth <mode> -k <32-byte key in hexadecimal> -i <input file> -o <outputfile>")
	fmt.Println("set <mode> as 'encrypt' or 'decrypt'")

}

//Funciton to setup the CLI
func setupCLI() (string, string, string, string) {

	var mode string
	var keyPtr string
	var inputPtr string
	var outputPtr string

	encryptCommand := flag.NewFlagSet("encrypt", flag.ExitOnError)
	decryptCommand := flag.NewFlagSet("decrypt", flag.ExitOnError)

	encryptKeyPtr := encryptCommand.String("k", "", "32 byte hexadecimal key")
	encryptInputPtr := encryptCommand.String("i", "", "location of raw binary data input text file")
	encryptOutputPtr := encryptCommand.String("o", "", "location of raw binary data output text file")

	decryptKeyPtr := decryptCommand.String("k", "", "32 byte hexadecimal key")
	decryptInputPtr := decryptCommand.String("i", "", "location of raw binary data input text file")
	decryptOutputPtr := decryptCommand.String("o", "", "location of raw binary data output text file")

	if len(os.Args) < 2 {

		missingParametersError()
		encryptCommand.PrintDefaults()
		os.Exit(1)

	}

	switch os.Args[1] {
	case "encrypt":
		mode = "encrypt"
		encryptCommand.Parse(os.Args[2:])
		keyPtr = *encryptKeyPtr
		inputPtr = *encryptInputPtr
		outputPtr = *encryptOutputPtr

	case "decrypt":
		mode = "decrypt"
		decryptCommand.Parse(os.Args[2:])
		keyPtr = *decryptKeyPtr
		inputPtr = *decryptInputPtr
		outputPtr = *decryptOutputPtr
	default:
		missingParametersError()
		encryptCommand.PrintDefaults()
		os.Exit(1)
	}

	if keyPtr == "" || inputPtr == "" || outputPtr == "" {
		missingParametersError()
		encryptCommand.PrintDefaults()
		os.Exit(1)
	}

	// fmt.Printf("mode: %s, key: %s, input: %s, output: %s\n", mode, keyPtr, inputPtr, outputPtr)
	return mode, keyPtr, inputPtr, outputPtr

}

//Function that converts a string of binary to a string of hexadecimal => coverts every 4 bits of binary to hexadecimal
func binToHex(binaryText string) string {

	var hexText string

	for i := 0; i < len(binaryText); i += 4 {

		binaryTextPart := binaryText[0+i : 4+i]
		hexText += binHexMap[binaryTextPart]
	}
	return hexText
}

//Function that converts a string of hexadecimal to a string of binary => coverts every 1 hexadecimal value to binary
func hexToBin(hexText string) string {

	var binaryText string

	for i := 0; i < len(hexText); i++ {

		hexTextPart := hexText[0+i : 1+i]

		binaryText += hexBinMap[hexTextPart]
		// fmt.Println("hex text part: ", hexTextPart, hexBinMap[hexTextPart])
	}
	return binaryText
}

//Function to get the binary value from the given input file and return hexadecimal value
func getInputText(inputText string) string {

	file, err := os.Open(inputText)
	if err != nil {
		log.Fatal(err)
	}

	dataBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	binaryText := string(dataBytes)

	size := len(binaryText)

	if size%8 != 0 {

		fmt.Println("ERROR: Please provide the input text with octet strings of raw binary data - ", size%8, " extra bits")
		os.Exit(1)
	}

	// fmt.Println("text: ", binaryText)

	return binToHex(binaryText)
}

//Function to perform XOR of two n/2 bytes hexadecimals and returns result in hexadecimal
func hexXOR(input1 string, input2 string, n int) string {

	var s string

	// fmt.Println(input1, len(input1))
	// fmt.Println(input2, len(input2))

	for i := 0; i < n; i += 16 {

		x, _ := strconv.ParseUint(input1[0+i:16+i], 16, 64)
		y, _ := strconv.ParseUint(input2[0+i:16+i], 16, 64)
		z := x ^ y
		h := fmt.Sprintf("%x", z)
		n := len(h)
		for i := 16 - n; i != 0; i-- {
			h = "0" + h
		}
		// fmt.Println("Hex: ", h)
		s += fmt.Sprintf("%s", h)

	}

	return s

}

//Funciton to get integer byte array from hexadecimal values
func hexToBytes(hexadecimal string) []byte {

	n := len(hexadecimal)
	var intBytes = make([]byte, int(n/2))

	for i := 0; i < len(intBytes); i++ {
		x, _ := strconv.ParseUint(hexadecimal[0+i*2:2+i*2], 16, 64)
		intBytes[i] = byte(x)
	}

	return intBytes
}

//Function to generate the random IV
func generateIV() string {

	var s string
	key := [16]byte{}
	_, err := rand.Read(key[:])
	if err != nil {
		panic(err)
	}
	// fmt.Println(key)

	for i := 0; i < len(key); i++ {
		h := fmt.Sprintf("%x", key[i])
		s += fmt.Sprintf("%s", h)
	}
	n := len(s)
	for i := 32 - n; i != 0; i-- {
		s = "0" + s
	}
	return s
}

//Function to set the output in text file
func setOutputText(text, output string) {

	var _, err = os.Stat(output)

	// delete file if exists
	if os.IsExist(err) {

		err = os.Remove(output)
		if err != nil {
			log.Fatal(err)
			fmt.Println("ERROR: cannot open: ", err)
		}

	}

	file, err := os.Create(output)
	if err != nil {
		log.Fatal(err)
		fmt.Println("ERROR: cannot open: ", err)
	}

	file, err = os.OpenFile(output, os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatal(err)
		fmt.Println("ERROR: cannot open: ", err)
	}

	l, err := file.WriteString(text)
	if err != nil {
		fmt.Println("ERROR: cannot write", err)
		file.Close()
		return
	}
	fmt.Println(l, "bits written successfully to the file", output)
	file.Sync()
	file.Close()
}

func bigIntToHex(n *big.Int) string {
	return fmt.Sprintf("%x", n)
}

// Function that takes 2 hexadecimal inputs of 16 bytes and finds its sum and returns the sum in hexadecimal form according to the need
func getSum(input1 string, input2 string, modN bool) string {

	// fmt.Println("input 1: ", input1)
	// fmt.Println("input 2: ", input2)

	var integer1 big.Int
	var integer2 big.Int
	var sum big.Int
	var N big.Int

	integer1.SetString(input1, 16)
	integer2.SetString(input2, 16)
	N.SetInt64(256)

	// fmt.Println("input hex 1: ", &integer1)
	// fmt.Println("input hex 2: ", &integer2)
	sum.Add(&integer1, &integer2)
	// fmt.Println("input hex 3: ", &sum)

	if modN {

		sum.Mod(&sum, &N)
	}

	output := bigIntToHex(&sum)

	if !modN {

		n := len(output)
		for i := 32 - n; i != 0; i-- {
			output = "0" + output
		}

	}

	// fmt.Println("sum: ", output)
	return output
}

// Function that takes the whole plaintext in hexadecimal and returns the getChecksum also in hexadecimal
func getChecksum(plaintext string) string {

	var sum uint32
	sum = crc32.ChecksumIEEE(hexToBytes(plaintext))

	fmt.Println("Checksum in integer: ", sum)
	checksum := fmt.Sprintf("%x", sum)

	if len(checksum) < 8 {
		checksum = duplicateZeros1(8-len(checksum)) + checksum
	}

	return checksum
}

//Makes the block size (16 bytes) proper by appending n "00" byte(s) in front of the string
func duplicateZeros1(n int) string {
	var zero string
	for i := 0; i < n; i++ {
		zero += "0"
	}

	return zero
}

//Makes the block size (16 bytes) proper by appending n "00" byte(s) in front of the string
func duplicateZeros(n int) string {
	var zero string
	for i := 0; i < n; i++ {
		zero += "00"
	}

	return zero
}

//Funciton that performs the AES-CTR encryption
func aesctrEncrypt(key, iv, message string) string {

	var byteEncrypted []byte
	var hexEncrypted string
	var ciphertext string
	var i int
	var check bool
	// c :=  make(map[int]string)
	ivs := make(map[int]string)

	keyEncryption := hexToBytes(key)                   // this key will bbe used for the whole AES-CBC mode encryption
	aesEncryption, err := aes.NewCipher(keyEncryption) // this the AES-ECB mode that enciphers using the key
	if err != nil {
		fmt.Println(err)
	}

	// fmt.Println(message[0:32])
	// fmt.Println(message[32:64])
	// fmt.Println(message[64:96])
	// fmt.Println(iv)
	ivs[0] = iv
	ciphertext += hexToBin(ivs[0])
	checkLen := len(message) % 32
	if checkLen != 0 {
		check = true
	} else {
		check = false
	}

	fmt.Println("message: ", int(len(message)))
	fmt.Println("number of blocks: ", int(len(message)/32))
	fmt.Println("last block size: ", int(len(message)%32))

	for i = 0; i < int(len(message)/32); i++ {

		// fmt.Println("hello:", i)
		messagePart := message[0+i*32 : 32+i*32]
		// fmt.Println("iv: ", c[i], len(c[i]))
		// fmt.Println("message block: ", messagePart, len(messagePart))
		block := hexToBytes(ivs[i])
		fmt.Println("iv: ", ivs[i], len(ivs[i]))
		fmt.Println("block: ", block, len(block))
		byteEncrypted = make([]byte, 16)
		aesEncryption.Encrypt(byteEncrypted, block)
		hexEncrypted = fmt.Sprintf("%x", byteEncrypted)
		cipherTextPart := hexXOR(hexEncrypted, messagePart, 32)
		// fmt.Println("Encrypted Before: ", hexEncrypted)
		// fmt.Println("Message: ", messagePart, len(messagePart))
		// fmt.Println("Encrypted: ", cipherTextPart)
		// test := hexXOR(cipherTextPart, hexEncrypted, 32)
		// fmt.Println("Decrypted: ", test)
		// hexDecrypted := fmt.Sprintf("%x", byteDecrypted)
		// fmt.Println("Decrypted: ", hexDecrypted)
		// ivPart1 := ivs[i][0:16]
		// ivPart2 := ivs[i][16:32]
		// ivPart2 = fmt.Sprintf("%x", summation(ivs[i], "0000000000000001"))
		// ivs[i+1] = ivPart1 + ivPart2
		ivs[i+1] = getSum(ivs[i], hexOne16, false)
		// fmt.Println("hex cipher: ", hexEncrypted)
		ciphertext += hexToBin(cipherTextPart)

	}

	if check {

		messagePart := message[i*32 : len(message)]
		fmt.Println("Last block again: ", messagePart, len(messagePart))
		size := int(len(messagePart) / 2)
		fmt.Println("size of last block: ", size)
		messagePart = duplicateZeros(16-size) + messagePart
		fmt.Println("Last block again and again: ", messagePart, len(messagePart))
		block := hexToBytes(ivs[i])
		byteEncrypted = make([]byte, 16)
		aesEncryption.Encrypt(byteEncrypted, block)
		hexEncrypted = fmt.Sprintf("%x", byteEncrypted)
		fmt.Println("Encrypted: ", hexEncrypted, len(hexEncrypted))
		hexEncrypted = hexEncrypted[0 : size*2]
		fmt.Println("Encrypted again: ", hexEncrypted, len(hexEncrypted))
		hexEncrypted = duplicateZeros(16-size) + hexEncrypted
		fmt.Println("Encrypted again and again: ", hexEncrypted, len(hexEncrypted))
		cipherTextPart := hexXOR(hexEncrypted, messagePart, 32)
		fmt.Println("XOR: ", cipherTextPart, len(cipherTextPart))
		cipherTextPart = cipherTextPart[len(cipherTextPart)-size*2 : len(cipherTextPart)]
		fmt.Println("XOR again: ", cipherTextPart, len(cipherTextPart))
		ciphertext += hexToBin(cipherTextPart)
	}
	// block := []byte(keyEncryption)
	// aesEncryption.Encrypt(block, []byte(keyEncryption))

	// ciphertext := decToBin(x)
	// fmt.Println(ciphertext)
	return ciphertext
}

//Funciton that performs the AES-CTR encryption
func aesctrDecrypt(key, ciphertext string) string {

	var byteDecrypted []byte
	var hexDecrypted string
	var plaintext string
	var ciphertextOnly string
	var plaintextWithoutChecksum string
	var checksumActual string
	var size int
	var i int
	var check bool
	// c :=  make(map[int]string)
	ivs := make(map[int]string)

	keyEncryption := hexToBytes(key)                   // this key will bbe used for the whole AES-CBC mode encryption
	aesEncryption, err := aes.NewCipher(keyEncryption) // this the AES-ECB mode that enciphers using the key
	if err != nil {
		fmt.Println(err)
	}

	// fmt.Println(message[0:32])
	// fmt.Println(message[32:64])
	// fmt.Println(message[64:96])
	// fmt.Println(iv)
	ivs[0] = ciphertext[0:32]
	ciphertextOnly = ciphertext[32:len(ciphertext)]

	checkLen := len(ciphertextOnly) % 32
	size = int(len(ciphertextOnly) / 32)
	if checkLen != 0 {
		check = true
	} else {
		check = false
	}
	fmt.Println("iv: ", ivs[0], len(ivs[0]))
	fmt.Println("ciphertext: ", ciphertextOnly, len(ciphertextOnly))
	fmt.Println("number of blocks: ", size)
	fmt.Println("last block size: ", checkLen)

	for i = 0; i < size; i++ {

		// fmt.Println("hello:", i)
		messagePart := ciphertextOnly[0+i*32 : 32+i*32]
		// fmt.Println("iv: ", c[i], len(c[i]))
		// fmt.Println("message block: ", messagePart, len(messagePart))
		block := hexToBytes(ivs[i])
		// fmt.Println("iv: ", ivs[i], len(ivs[i]))
		// fmt.Println("block: ", block, len(block))
		// fmt.Println("message block in bytes: ", hexXOR(c[i], messagePart, 32), block, len(block))
		byteDecrypted = make([]byte, 16)
		aesEncryption.Encrypt(byteDecrypted, block)
		hexDecrypted = fmt.Sprintf("%x", byteDecrypted)
		plaintTextPart := hexXOR(hexDecrypted, messagePart, 32)
		// fmt.Println("Encrypted: ", hexEncrypted)
		// hexDecrypted := fmt.Sprintf("%x", byteDecrypted)
		// fmt.Println("Decrypted: ", hexDecrypted)
		// ivPart1 := ivs[i][0:16]
		// ivPart2 := ivs[i][16:32]
		// ivPart2 = fmt.Sprintf("%x", summation(ivPart2, "0000000000000001"))
		// ivs[i+1] = ivPart1 + ivPart2
		ivs[i+1] = getSum(ivs[i], hexOne16, false)
		// fmt.Println("hex cipher: ", hexEncrypted)
		plaintext += plaintTextPart

	}

	if check {

		messagePart := ciphertextOnly[i*32 : len(ciphertextOnly)]
		fmt.Println("Checksum again: ", messagePart, len(messagePart))
		size := int(len(messagePart) / 2)
		fmt.Println("size of last block: ", size)
		messagePart = duplicateZeros(16-size) + messagePart
		fmt.Println("Checksum again and again: ", messagePart, len(messagePart))
		block := hexToBytes(ivs[i])
		byteDecrypted = make([]byte, 16)
		aesEncryption.Encrypt(byteDecrypted, block)
		hexDecrypted = fmt.Sprintf("%x", byteDecrypted)
		fmt.Println("Encrypted again: ", hexDecrypted, len(hexDecrypted))
		hexDecrypted = hexDecrypted[0 : size*2]
		fmt.Println("Encrypted again and again: ", hexDecrypted, len(hexDecrypted))
		hexDecrypted = duplicateZeros(16-size) + hexDecrypted
		plainTextPart := hexXOR(hexDecrypted, messagePart, 32)
		plainTextPart = plainTextPart[len(plainTextPart)-size*2 : len(plainTextPart)]
		plaintext += plainTextPart

	}

	n := len(ciphertextOnly)
	checksumActual = plaintext[n-8 : n]
	plaintextWithoutChecksum = plaintext[0 : n-8]
	checksumExpected := getChecksum(plaintextWithoutChecksum)

	fmt.Println("Actual checksum: ", checksumActual)
	fmt.Println("Expected checksum: ", checksumExpected)
	fmt.Println("Plain text: ", plaintextWithoutChecksum)

	if checksumExpected != checksumActual {

		fmt.Println("ERROR: Invalid Checksum")
		os.Exit(0)
	} else {

		plaintext = plaintextWithoutChecksum
	}

	return plaintext
}

func main() {

	var mode string
	var input string
	var output string

	var aesKey string
	var messageAndChecksum string

	mode, aesKey, input, output = setupCLI()
	// aesKey = "6368616e676520746869732070617373" //example

	// mode = "encrypt"
	// input = "input.txt"
	// output = "output.txt"
	// mode = "decrypt"
	// input = "output.txt"
	// output = "input.txt"

	switch mode {

	case "encrypt":

		setupBinHexMap()
		setupHexBinMap()
		plaintext := getInputText(input)
		fmt.Println("Encrypting Plain Text... ") // input file name from CLI
		fmt.Println("Plaintext: ", plaintext, len(plaintext))
		// Step 1. CHECKSUM algorithm
		checksumValue := getChecksum(plaintext)
		fmt.Println("Checksum: ", checksumValue)
		// Step 2. M′ = T||M
		messageAndChecksum = plaintext + checksumValue
		fmt.Println(messageAndChecksum, len(messageAndChecksum))
		// Step 3. AES-CTR
		iv := generateIV()
		// fmt.Println(iv)
		cipherText := aesctrEncrypt(aesKey, iv, messageAndChecksum)
		fmt.Println("ciphertext: ", binToHex(cipherText), len(binToHex(cipherText))) //, len(cipherText)) // store in cipher in output text
		setOutputText(cipherText, output)
		fmt.Println("Encryption Complete")

	case "decrypt":
		setupBinHexMap()
		setupHexBinMap()
		cipherText := getInputText(input) // from CLI
		fmt.Println("Cipher text: ", cipherText, len(cipherText))
		fmt.Println("Decrypting Cipher Text... ")      // len(cipherText))
		plaintext := aesctrDecrypt(aesKey, cipherText) // from CLI split keys
		fmt.Println(plaintext, len(plaintext))
		fmt.Println("final plain text: ", hexToBin(plaintext))
		plaintext = hexToBin(plaintext)
		setOutputText(plaintext, output)
		fmt.Println("Decryption Complete")

	}
	// fmt.Println(hexXOR("d09a798087ed81202e5c96315d4eb852", "7343dfa2b8950ca0504b07ce73083dee", 32))
	// fmt.Println(mode, key, input, output)

}
