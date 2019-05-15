# COMP3260_Assignment2

Java implementation of 10 round AES encryption and decryption exploring the [Avalanche effect](https://en.wikipedia.org/wiki/Avalanche_effect)
on plaintexts that differ by 1 bit by altering the inclusion of certain operations in the rounds.

## Compilation
"javac Application.java"

## Execution
"java Application" to run the program. Command lines arguments are optional and if they are excluded then you will be prompted by a couple dialogs to choose mode and  input file.
No output file is required as an input. The output of execution will be printed to standard output and to a file named "input_filname_output.txt".

### Command Line Args
--encrypt input_filename
for encryption.

--decrypt input_filename
for decryption.

***Examples***

"java Application --encrypt Example.txt"
"java Application --decrypt C:/Users/Name/Documents/Example.dat"

## Sources
* Federal Information Processing Standards Publication 197, Announcing the ADVANCED ENCRYPTION STANDARD (AES) 
	- November 26, 2001,
	- https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf


