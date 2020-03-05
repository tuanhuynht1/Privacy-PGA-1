#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>

#include <tomcrypt.h>

#define KEYSIZE 16
#define BUFFER_SIZE 1024
using namespace std;

unsigned char key[KEYSIZE] = "123456789012345";
unsigned char IV[KEYSIZE] = "bbcdefhij12345";

void pseudo_random_generator(unsigned char* arr, int keysize)
{
    prng_state prng;
    unsigned char buf[keysize] = "bsn-2205";

    /* start it */
    sober128_start(&prng);
    
    /* add entropy */
    sober128_add_entropy(buf, 9, &prng);

    /* ready */
    sober128_ready(&prng);

    /* read */
    sober128_read(buf, keysize, &prng);
    
    memcpy(arr, buf, keysize);
}

void decrypt_OTP(char* cipher_text, char* message, int keysize)
{
    unsigned char key[keysize];
    pseudo_random_generator(key, keysize);
    
    for(int i = 0; i < keysize; i++)
    {
        message[i] = cipher_text[i] ^ key[i];
    }
}

int Dec(unsigned char* key, unsigned char* cipher);

int main () {
    //  Prepare our context and socket
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REP);
    socket.bind ("tcp://*:55558");

    int i = 0;

    cout << "SERVER ONLINE" << endl;

    while (true) {
        unsigned char recv_arr[BUFFER_SIZE];

        //  Wait for next request from client
        socket.recv(recv_arr, BUFFER_SIZE);
        //cout << recv_arr << endl;
        Dec(key,recv_arr);
        cout << recv_arr << endl;
        socket.send(to_string(i).c_str(), BUFFER_SIZE);
        i++;

    }
    return 0;
}

int Dec(unsigned char* key, unsigned char* cipher){
    
    unsigned char buffer[BUFFER_SIZE];
    memcpy(buffer,cipher,BUFFER_SIZE);

    symmetric_CTR ctr;
    int x, err;

    /* register twofish first */
    if (register_cipher(&twofish_desc) == -1)
    {
        printf("Error registering cipher.\n");
        return -1;
    }

    /* somehow fill out key and IV */
    /* start up CTR mode */
    if ((err = ctr_start(
             find_cipher("twofish"),    /* index of desired cipher */
             IV,                        /* the initial vector */
             key,                       /* the secret key */
             16,                        /* length of secret key (16 bytes) */
             0,                         /* 0 == default # of rounds */
             CTR_COUNTER_LITTLE_ENDIAN, /* Little endian counter */
             &ctr)                      /* where to store the CTR state */
         ) != CRYPT_OK)
    {
        printf("ctr_start error: %s\n", error_to_string(err));
        return -1;
    }


    /* make use of ciphertext... */
    /* now we want to decrypt so let’s use ctr_setiv */
    if ((err = ctr_setiv(IV,   /* the initial IV we gave to ctr_start */
                         16,   /* the IV is 16 bytes long */
                         &ctr) /* the ctr state we wish to modify */
         ) != CRYPT_OK)
    {
        printf("ctr_setiv error: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = ctr_decrypt(buffer,         /* ciphertext */
                           cipher,         /* plaintext */
                           sizeof(buffer), /* length of plaintext */
                           &ctr)           /* CTR state */
         ) != CRYPT_OK)
    {
        printf("ctr_decrypt error: %s\n", error_to_string(err));
        return -1;
    }

    /* terminate the stream */
    if ((err = ctr_done(&ctr)) != CRYPT_OK)
    {
        printf("ctr_done error: %s\n", error_to_string(err));
        return -1;
    }
    /* clear up and return */
    // zeromem(key, sizeof(key));
    // zeromem(&ctr, sizeof(ctr));
    return 0;

}

