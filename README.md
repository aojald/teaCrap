# teaCrap
## What is TeaCrap ?
TeaCrap is a small java app to recover password stored using [Tiny Encryption Algorithm](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) which you should never use in production.
## How to ?
1. Configure : change the key in `teaCrap.java`
2. compile : `javac teaCrap.java`
3. put the password you want to "recover" in `teaPass.txt`
4. Exec : `java teaCrap`
5. Enjoy ;)

## Why ?
Because i needed it for a pentest ;) and it helps me recover more than 3000 passwords in plain text.
The "cypher" typo helps me in the first place to find this crapy "crypto" fucntion.
