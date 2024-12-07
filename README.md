# Python implementation of RSA
## The algorithm
1. Choose 2 big large prime numbers $p$, $q$
2. Calculate $n = p \cdot q$
3. Calculate Euler's phi function $\phi(n)$
    * Phi functions calculated number of co-prime numbers to $n$ lower than $n$
    * Co-prime means that the greatest common divisor (gcd) of the number and n is equal to 1 i.e. $gcd(m, n) = 1$
    * Gcd of 2 numbers can be calculated using the Euclidean algorithm, which is **expensive for large n**!
    * Since $n = p \cdot q$ the Phi function can be calculated as $\phi(p \cdot q) = (p - 1) \cdot (q - 1)$
4. Choose the public key from $\{1, 2, 3, \dots, \phi(n) - 1\}$ s.t. $gcd(e, \phi(n)) = 1$
    * We need the numbers to be co-prime because we want to be able to calculate an inverse of the $e$
5. Compute the private key $d \cdot e \equiv 1 \mod \phi(n) $
6. Given a message $x \in Z_n\{0, \dots, n - 1\}$ we can:
    * Encode: $x^e \mod n$
    * Decode: $y^d \mod n$
    * Since $e$ and $d$ are both large numbers we have to employes a fast exponentiation algorithm (TODO: support negative exponents)
    * Limitation on the size of the x! That means that this canno't be used to encoding larger messages (in theory it can by dividing the message in block, but that's not used in practice. In practices the RSA is used to encode a symetric key of a block cypher, and the data is then encoded using that)