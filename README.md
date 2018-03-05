# vulnrh
[V]ery [U]nsecure &amp; [L]acki[n]g [R]aspberry pi [H]SM
_project for TEIT3B29INFOA(labo µsystèmes)_

## __Very Unsecure__
This is solely for learning/training purposes, i.e. It's shit.

## TODO
* [In PROGRESS] replace fork() and use proper multithreading (pthread.h ?)
  * use a queue/stack of all threads and force their shutdown in case of force shutdown of mainprocess
  * ~~add mutexes~~ mutexes are slow as fuck, use spinlock.
  * *async send/receive with a callback (?)*
* clean up code
* """secure""" it
    * stop using ECB
    * use randomly generated key
    * put the keys in encrypted file (is the enc useful? What about its key ? Shoudl I prompt user ? Can I re-use GPG for that ?)
    * use SSL & secure communication with client over network
* ~~replace the keymap : linkedlist~~
* read a fucking book on HSMs
