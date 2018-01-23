# vulnrh
[V]ery [U]nsecure &amp; [L]acki[n]g [R]aspberry pi [H]SM
_project for TEIT3B29INFOA(labo µsystèmes)_

## __Very Unsecure__
There are various things I didn't took care of. Others I simply won't be able
to, because of skills or time. 
I plan on gradually securing it though, as I learn more about cryptosystems.

## TODO
* clean up code
* secure it
    * stop using ECB
    * use randomly generated key
    * put the keys in encrypted file (?? is this useful. should I put the key of it in another file ?)
    * use SSL & secure communication with client over network
* read a book on HSMs

## problems
### keys in a file
The problem of this is securing the file itself.
One idea would be to encrypt that file and have the key somewhere in a safe place. The location of the key could be passed as a parameter when starting vulnrh, and we'd read the content of it, rebuilding the keymap.
The single point of failure become the keyfile itself. And Everything in memory should be correctly protected also wiped out.
This becomes very complicated to implement, and therefore should probably not be a priority. Afterall the whole table is in memory, and should completely be protected too.