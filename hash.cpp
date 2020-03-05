#include<tomcrypt.h>
#include <cstring>
#include<iostream>

int main()
{
    hash_state md;
    unsigned char in[]= "hello world" ;
    unsigned char out[16];

    md5_init(&md);
    md5_process(&md, in, 16);
    md5_done(&md, out);
    std::cout << out << std::endl;

    return 0;

    
}