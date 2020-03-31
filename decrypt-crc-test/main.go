package main

import (
	"crypto/aes"
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
func setupCLI() string {

	var input string

	InputPtr := flag.String("i", "", "location of raw binary data cipher text file")

	if len(os.Args) < 2 {

		missingParametersError()
		flag.PrintDefaults()
		os.Exit(1)

	}

	flag.Parse()

	input = *InputPtr

	if input == "" {
		missingParametersError()
		flag.PrintDefaults()
		os.Exit(1)
	}

	return input

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

	if size == 0 {
		fmt.Println("ERROR: Input file is empty")
		fmt.Println("Please provide the input text with octet strings of raw binary data")
		os.Exit(1)
	}

	if size%8 != 0 {

		fmt.Println("ERROR: Please provide the input text with octet strings of raw binary data")
		os.Exit(1)
	}

	// fmt.Println(binaryText)
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

// Function that takes big.Int and returns its equivalent hexadecimal value
func bigIntToHex(n *big.Int) string {
	return fmt.Sprintf("%x", n)
}

// Function that takes 2 hexadecimal inputs of 16 bytes and finds its sum and returns the sum in integer form
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

//Makes the block size (16 bytes) proper by appending n "00" byte(s) in front of the string
func duplicateZeros(n int) string {
	var zero string
	for i := 0; i < n; i++ {
		zero += "00"
	}

	return zero
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

//Funciton that performs the AES-CTR encryption
func aesctrDecrypt(key, ciphertext string) string {

	var byteDecrypted []byte
	var hexDecrypted string
	var plaintext string
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
	ciphertext = ciphertext[32:len(ciphertext)]

	checkLen := len(ciphertext) % 32
	size = int(len(ciphertext) / 32)
	if checkLen != 0 {
		check = true
	} else {
		check = false
	}
	fmt.Println("number of blocks: ", size)
	fmt.Println("last block size: ", checkLen)

	for i = 0; i < size; i++ {

		// fmt.Println("hello:", i)
		messagePart := ciphertext[0+i*32 : 32+i*32]
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
		ivs[i+1] = getSum(ivs[i], hexOne16, false)
		// fmt.Println("hex cipher: ", hexEncrypted)
		plaintext += plaintTextPart

	}

	if check {

		messagePart := ciphertext[i*32 : len(ciphertext)]
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

	n := len(ciphertext)
	checksumActual = plaintext[n-8 : n]
	plaintextWithoutChecksum = plaintext[0 : n-8]
	checksumExpected := getChecksum(plaintextWithoutChecksum)

	fmt.Println("Actual checksum: ", checksumActual)
	fmt.Println("Expected checksum: ", checksumExpected)
	fmt.Println("Plain text: ", plaintextWithoutChecksum)

	if checksumExpected != checksumActual {

		return "INVALID CHECKSUM"
	}

	return "SUCCESS"
}

func main() {

	var input string

	input = setupCLI()
	aesKey := "6368616e676520746869732070617373"

	setupBinHexMap()
	setupHexBinMap()

	cipherText := getInputText(input) // from CLI
	// fmt.Println("Decrypt Test Starting... ", cipherText) //, len(cipherText))
	result := aesctrDecrypt(aesKey, cipherText) //from CLI split keys

	// fmt.Println("Decryption Test Complete")
	fmt.Println(result)

	// fmt.Println(hexXOR("d09a798087ed81202e5c96315d4eb852", "7343dfa2b8950ca0504b07ce73083dee", 32))
	// fmt.Println(mode, key, input, output)

}
