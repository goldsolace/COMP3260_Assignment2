# COMP3260_Assignment2

Java implementation of 10 round AES encryption and decryption exploring the [Avalanche effect](https://en.wikipedia.org/wiki/Avalanche_effect)
on plaintexts that differ by 1 bit by altering the inclusion of certain operations in the rounds.

## Compilation
javac Application.java

## Execution
Call java Application to run the program. Command lines arguments are optional and if they are excluded then you will be prompted by a couple dialogs to choose mode and file

### Command Line Args
<executable name> --encrypt <input filename> <output filename>
for encryption.

<executable name> --decrypt <input filename> <output filename>
for decryption.

***Examples***

"java Application --encrypt Example.txt"
"java Application -decrypt C:/Users/Name/Documents/Example.dat"

## Sources
* Federal Information Processing Standards Publication 197, Announcing the ADVANCED ENCRYPTION STANDARD (AES) 
	- November 26, 2001,
	- https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf


