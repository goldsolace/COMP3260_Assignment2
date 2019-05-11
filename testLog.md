# Test Log

## Tips
When testing, the methods printBinary and printHex should be used to see the
contents of the state or the roundkey

## 10 round encryption (without avalanche)
### The following 10 round encryption was successfuly verified via the link below
https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf

Corresponding example results can be found under Appendix C - Example Vectors,
C.1 AES-128

input: 0112233445566778899aabbccddeeff<br />
start: 0102030405060708090a0b0c0d0e0f0<br />
s_box: 63cab74953d051cd60e0e7ba70e18c<br />
s_rows: 6353e08c960e14cd70b751bacad0e7<br />
m_col: 5f72641557f5bc92f7be3b291db9f91a<br />
add round key<br />
start: 89d810e8855ace682d1843d8cb128fe4<br />
s_box: a761ca9b97be8b45d8ad1a611fc97369<br />
s_rows: a7be1a6997ad739bd8c9ca451f618b61<br />
m_col: ff87968431d86a51645151fa773ad09<br />
add round key<br />
start: 4915598f55e5d7a0daca94fa1fa63f7<br />
s_box: 3b59cb73fcd9ee05774222dc067fb68<br />
s_rows: 3bd92268fc74fb735767cbe0c059e2d<br />
m_col: 4c9c1e66f771f0762c3f868e534df256<br />
add round key<br />
start: fa636a2825b339c940668a3157244d17<br />
s_box: 2dfb2343f6d12dd9337ec75b36e3f0<br />
s_rows: 2d6d7ef03f33e3349362dd5bfb12c7<br />
m_col: 6385b79ffc538df997be478e7547d691<br />
add round key<br />
start: 247240236966b3fa6ed2753288425b6c<br />
s_box: 3640926f9336d2d9fb59d23c42c3950<br />
s_rows: 36339d50f9b539269f2c92dc4406d23<br />
m_col: f4bcd45432e554d075f1d6c51dd03b3c<br />
add round key<br />
start: c81677bc9b7ac93b2527992b0261996<br />
s_box: e847f56514dadde23f77b64fe7f7d490<br />
s_rows: e8dab6901477d4653ff7f5e2e747dd4f<br />
m_col: 9816ee740f87f556b2c49c8e5ad036<br />
add round key<br />
start: c62fe19f75eedc3cc79395d84f9cf5d<br />
s_box: b415f816858552e4bb6124c5f998a4c<br />
s_rows: b458124c68b68a14b99f82e5f15554c<br />
m_col: c57e1c159a9bd286f05f4be098c63439<br />
add round key<br />
start: d1876cf79c430ab45594add66ff41f<br />
s_box: 3e175076b61c4678dfc2295f6a8bfc0<br />
s_rows: 3e1c22c0b6fcbf768da85067f617495<br />
m_col: baa03de7a1f9b56ed5512cba5f414d23<br />
add round key<br />
start: fde3bad25e5d0d73547964ef1fe37f1<br />
s_box: 5411f4b56bd970e96a0902fa1bb9aa1<br />
s_rows: 54d990a16ba09ab596bbf4ea111702f<br />
m_col: e9f74eec23020f61bf2ccf2353c21c7<br />
add round key<br />
start: bd6e7c3df2b5779eb61216e8b10b689<br />
Output: 69c4e0d86a7b430d8cdb78070b4c55a<br />
