# vulnrh
[V]ery [U]nsecure &amp; [L]acki[n]g [R]aspberry pi [H]SM
_project for TEIT3B29INFOA(labo µsystèmes)_

## __Very Unsecure__
This is solely for learning/training purposes. It's shit.

## TODO
* replace fork() and use proper multithreading (pthread.h ?)
  * add mutexes
  * *async send/receive with a callback (?)*
* clean up code
* """secure""" it
    * stop using ECB
    * use randomly generated key
    * put the keys in encrypted file (?? is this useful. should I put the key of it in another file, should I ask the user ? Can I re-use GPG for that ?)
    * use SSL & secure communication with client over network
* read a fucking book on HSMs
* [X] replace the keymap : linkedlist
