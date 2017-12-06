# hash-collision-attack
A Hash Collision Attack is an attempt to find two input strings of a hash function that produce the same hash result. Because hash functions have infinite input length and a predefined output length, there is inevitably going to be the possibility of two different inputs that produce the same output hash. If two separate inputs produce the same hash output, it is called a collision. This collision can then be exploited by any application that compares two hashes together – such as password hashes, file integrity checks, etc.

# Example of use this Script in wargame pwnable.kr (collision)
```
root@kali:~/Desktop/Scripts# python3 hash-collision-attack.py --hashcode 0x21DD09EC --chunkbytes 5 --vulnapp col
[+]Hashcode: 0x21DD09EC
[+]Number of chunk bytes: 5
[+]Vulnapp: col
[+] EXPLOTATION:
     '\xc8\xce\xc5\x06'
     '\xcc\xce\xc5\x06'
[+] PYTHON EXPLOIT CODE: ./col $(python -c "print('\xc8\xce\xc5\x06'*4+'\xcc\xce\xc5\x06')")
you get it the flag
```
# Example in wargame pwnable.kr (collision)

ssh col@pwnable.kr -p2222 (pw:guest)

So there are three files of interest here, col, col.c, and flag. Similar to the fd challenge, flag is owned by the user col2 and we don’t have read permissions to view it, and again the suid flag is set on the file col.
```
col@ubuntu:~$ ./col 
usage : ./col [passcode] 
col@ubuntu:~$ ./col AAAA 
passcode length should be 20 bytes 
col@ubuntu:~$ ./col AAAABBBBCCCCDDDDEEEE 
wrong passcode.
```
So it wants us to enter a 20 byte passcode, and obviously compares it to something as apparently our 20 byte passcode is wrong. Let’s take a look at the source…

If we look at vulnerable source code:
```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){     // returns an unsigned long (at least 4 bytes)
    int* ip = (int*)p;                         // casts p (20 bytes) to an integer pointer (4 bytes)
    int i;                                // counter
    int res=0;                            // holds the result
     // Iterate over the char array 4 bytes a time, sum them up
    for(i=0; i<5; i++){                        // interates 5 times: (five 4 byte chucks of the input)
        res += ip[i];                        // adds each 4 byte chunk to the last
    }
    return res;                            // returns the 4 byte long
}

int main(int argc, char* argv[]){

// Check there are at least two arguments (including file name)
    if(argc<2){
        printf("usage : %s [passcode]\n", argv[0]);
        return 0;
    }

// Check arg[v] is of exactly 20 bytes
    if(strlen(argv[1]) != 20){
        printf("passcode length should be 20 bytes\n");
        return 0;
    }


// if hashcode matches returned value, print flag
    if(hashcode == check_password( argv[1] )){
        system("/bin/cat flag");
        return 0;
    }
    else
        printf("wrong passcode.\n");
    return 0;
}

```
As you can see from the code, the password length needs to be 20 bytes, which is equal to 5 integers (1 int = 4 bytes). The sum of the 5 integers from the input needs to be equal to 0x21DD09EC to obtain the flag. Let's find 5 integers that are in total equal to 0x21DD09EC

So in the source we can see, hashcode = 0x21DD09EC, which is later compared to the result of the function check_password(argv[1]). If they are the same this will cat our flag.

We can getting proof about the arquitecture:
```
col@ubuntu:~$ readelf -h col | head
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1

```
Since it's a 32-bit executable, pointers to int will have a size of 4 bytes. Thus our hashing function takes our 20 bytes, casts the char* into an int* (5 chunks of 4 bytes) and sums the integers relative to each chunk. Since our hashing function is not perfect, there will probably be many collisions. All we need is to find one. Let's check the value of 0x21DD09EC and divide it by five:

```
$ python -c "print(0x21DD09EC)" 
568134124 
$ python -c "print(0x21DD09EC/5)" 
113626824.8
```

Our result is not a round number. But it doesn't have to be anyways. Let's use 4 chunks of 113626824 and one for the remainder, then the flag is ours:
```
$ python -c "print(0x21DD09EC - 113626824*4)" 
113626828 
$ python -c "print(hex(113626824), hex(113626828))" 
0x6c5cec8 0x6c5cecc 
$ ./col $(python -c "print('\xc8\xce\xc5\x06'*4+'\xcc\xce\xc5\x06')")
daddy! I just managed to create a hash collision :)
```
More information about the attack:
https://learncryptography.com/hash-functions/hash-collision-attack
