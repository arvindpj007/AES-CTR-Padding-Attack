package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
	fmt.Println("decrypt-attack -i <input file>")
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

//Function that converts a string of hexadecimal to a string of binary => coverts every 1 hexadecimal value to 4 bits of binary
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

		fmt.Println("ERROR: The input file is empty.\n Please provide the input text with octet strings of raw binary data")
		os.Exit(1)
	}

	if size%8 != 0 {

		fmt.Println("ERROR: Please provide the input text with octet strings of raw binary data")
		os.Exit(1)
	}

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

//Funciton to set the check.txt file which is used by the oracle server for testing
func setCheckFile(text string) {

	var _, err = os.Stat("check.txt")

	// delete file if exists
	if os.IsExist(err) {

		err = os.Remove("check.txt")
		if err != nil {
			log.Fatal(err)
			fmt.Println("ERROR: cannot open: ", err)
		}

	}

	//create a clear file to write on
	file, err := os.Create("check.txt")
	if err != nil {
		log.Fatal(err)
		fmt.Println("ERROR: cannot open: ", err)
	}

	file, err = os.OpenFile("check.txt", os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatal(err)
		fmt.Println("ERROR: cannot open: ", err)
	}

	l, err := file.WriteString(text)
	// fmt.Println(text)
	if err != nil {
		fmt.Println("ERROR: cannot write", err)
		file.Close()
		return
	}
	// fmt.Println(l, "bits written successfully to the file")
	for i := 0; i < l; i++ {
		fmt.Print("")
	}
	file.Sync()
	file.Close()
}

//Function that returns the result after oracle processes the input from check.txt
func getDecryptTestResult() string {

	cmd := exec.Command("./decrypt-chk-test", "-i", "check.txt")
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println("Error in calling test function:", err)
		log.Fatal(err)
	}

	// fmt.Println("Full decrypt result: ", string(stdout))

	fullResult := strings.Split((string(stdout)), "\n")
	result := fullResult[len(fullResult)-2]
	if string(result[1]) == "SUCESS" {
		return "SUCCESS"
	}
	return result
}

//Function that partitions cipher texts to uniform blocks of 16 bytes + last block
func partitionCipherText(cipherText string) (string, []string, int) {

	var i int
	var iv string

	size := len(cipherText)
	checkLen := len(cipherText) % 32

	numberOfPartitions := int(size / 32)
	numberOfBlocks := numberOfPartitions
	if checkLen != 0 {
		numberOfBlocks++
	}

	iv = cipherText[0:32]

	// fmt.Println("cipher text: ", cipherText)
	// fmt.Println("number of blocks: ", numberOfPartitions)
	// fmt.Println("number of blocks: ", numberOfBlocks)

	var partedCipherText = make([]string, numberOfBlocks)

	for i = 1; i < numberOfPartitions; i++ {

		partedCipherText[i-1] = cipherText[i*32 : 32+i*32]
	}

	if checkLen != 0 {
		partedCipherText[i-1] = cipherText[i*32 : size]
	}

	return iv, partedCipherText, numberOfBlocks
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

//Function that returns n "00" byte(s) to make the block size (16 bytes) proper
func duplicateZeros(n int) string {
	var zero string
	for i := 0; i < n; i++ {
		zero += "00"
	}

	return zero
}

func oracleAttack(iv, cipherText string) string {

	var result string
	var input string
	var lastByte string
	var nextByte string
	var ciphertextPart string
	var ivDeciphered string
	var plaintext string
	var nCipherText int

	nCipherText = len(cipherText)
	size := int(nCipherText / 2)

	for j := 0; j < size; j++ {

		for i := 0; i < 256; i++ {

			lastByte = fmt.Sprintf("%x", i)
			if len(lastByte) == 1 {
				lastByte = "0" + lastByte
			}
			ciphertextPart = nextByte + lastByte
			input = iv + ciphertextPart
			setCheckFile(hexToBin(input))
			result = getDecryptTestResult()

			if result == "SUCCESS" {
				// fmt.Println("Checksum correct for ", lastByte)
				nextByte = nextByte + lastByte
				// fmt.Println("Last block: ", nextByte)
				break
			}

		}

	}

	if nCipherText < 32 {

		ivDeciphered = duplicateZeros(16-size) + nextByte
		fullCipherText := duplicateZeros(16-size) + cipherText
		plaintext = hexXOR(ivDeciphered, fullCipherText, 32)
		// fmt.Println("iv Deciphered: ", ivDeciphered)
		// fmt.Println("Cipher Text  : ", fullCipherText)
		// fmt.Println("Plain text: ", plaintext)
		plaintext = plaintext[len(plaintext)-nCipherText : len(plaintext)]
	} else {

		ivDeciphered = nextByte
		fullCipherText := cipherText
		plaintext = hexXOR(ivDeciphered, fullCipherText, 32)
		// fmt.Println("iv Deciphered: ", ivDeciphered)
		// fmt.Println("Cipher Text  : ", fullCipherText)
		// fmt.Println("Plain text: ", plaintext)
	}

	// input = iv + cipherText

	// setCheckFile(hexToBin(input))
	// x = getDecryptTestResult()
	return plaintext
}

func main() {

	var input string
	var iv string
	var cipherText string
	var plainText string
	var plaintextAndChecksum string // uncomment
	// var plaintextAndHmacAndPadding string
	var nextIV string
	var partedCipherText []string
	var numberOfPartitions int

	setupBinHexMap()
	setupHexBinMap()

	// fmt.Println("Decrypt Attack starting...")

	input = setupCLI()
	cipherText = getInputText(input)

	iv, partedCipherText, numberOfPartitions = partitionCipherText(cipherText)

	// setCheckFile(hexToBin())
	var partedPlainText = make([]string, numberOfPartitions) // uncomment

	// for i := numberOfPartitions - 1; i > 0; i-- {

	// 	partedPlainText[i] = oracleAttack(partedCipherText[i-1], partedCipherText[i])
	// }

	// fmt.Println("IV: ", iv)
	// fmt.Println("parted cipher texts: ", partedCipherText)
	// fmt.Println("number of partitions: ", numberOfPartitions)

	nextIV = iv

	// x := oracleAttack(nextIV, partedCipherText[0])

	// fmt.Println("x: ", x)
	for i := 0; i < numberOfPartitions; i++ {

		// fmt.Println("iteration ", i, " : ")
		partedPlainText[i] = oracleAttack(nextIV, partedCipherText[i])
		nextIV = getSum(nextIV, hexOne16, false)
		// fmt.Println(partedPlainText[i])
	}

	for i := 0; i < numberOfPartitions; i++ {
		plaintextAndChecksum += partedPlainText[i]
	}

	nPlaintextAndChecksum := len(plaintextAndChecksum)
	plainText = plaintextAndChecksum[2:nPlaintextAndChecksum]

	fmt.Println(hexToBin(plainText))
}
