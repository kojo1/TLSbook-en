## 3.3 hash

Hash, also called message digest, is a unidirectional algorithm for compressing long messages with indefinite length into short fixed length data.

The hash algorithm for obtaining the hash value is required to be (virtually) impossible to obtain a message having such a hash value from the hash value (difficulty in calculating the original image, weak collision resistance). I will. To do this, the algorithm must be such that the hash value changes significantly when the message is changed slightly, and the hash value appears to be uncorrelated with the hash value of the original message. It also requires that it is (virtually) impossible to find pairs of two different messages with the same hash value (strong collision resistance).

As a hash algorithm, MD5 by Ronald Rivest was standardized as RFC1321 in 1992, and then SHA1 and SHA2, which have a longer hash bit length and can be applied to large data, were standardized and widely used as a standard by NIST. SHA1 is a 160-bit hash algorithm, while SHA2 is a general term for a series of algorithms that obtain hash lengths from 224 bits to 512 bits. SHA2 is also called SHA256, SHA512, etc. for each hash length.

Cipher suites based on these have been adopted as standard in TLS, but in recent years, research on attacks related to MD5 and SHA1 has been reported, and there are concerns about the realization of attacks. Therefore, MD5 and SHA1 have been completely abolished in TLS 1.3.

MD5, SHA1 and SHA2 are based on the Merkle–Damgård construction algorithm, and due to concerns about dependence on this algorithm alone, SHA3 was established as a new standard. However, no specific risk has been reported for SHA2 at present, and SHA256 and SHA384 are adopted in TLS1.3.

<br> <br>
![Fig. 3-2](./fig3-2.jpg)
<br> <br>

Table 3-2 Main hash algorithms (from Wikipedia)