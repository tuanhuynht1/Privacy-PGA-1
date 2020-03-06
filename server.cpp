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

int Dec(unsigned char* key, unsigned char* cipher);
void Hash(unsigned char* message, unsigned char* hash);
void Hmac(unsigned char* k, unsigned char *message, char *mac);

int main () {

    //  Prepare our context and socket
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REP);
    socket.bind ("tcp://*:52558");

    int i = 0;
    cout << "SERVER ONLINE" << endl;
    
    unsigned char recv_arr[BUFFER_SIZE];
    unsigned char k_curr[KEYSIZE];
    unsigned char k_next[KEYSIZE];
    char mac[KEYSIZE];
    
    //initialize initial key
    memcpy(k_next,key,KEYSIZE);

    while (true) {


        //  Wait for next request from client
        socket.recv(recv_arr, BUFFER_SIZE);
        
        //update key
        memcpy(k_curr,k_next,KEYSIZE);

        //compute mac_i of cipher
        Hmac(k_curr,recv_arr,mac);

        // cout << recv_arr << endl;
        Dec(k_curr,recv_arr);
        // cout << recv_arr << endl;

        //hash key
        Hash(k_curr,k_next);

        // cout << mac << endl;
        for(auto c : mac){
            int i = c;
            cout << i << " ";
        }
        cout << endl;
        
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

void Hash(unsigned char* message, unsigned char* hash){
    hash_state sha1;
    sha1_init(&sha1);
    sha1_process(&sha1, message, KEYSIZE);
    sha1_done(&sha1, hash);
}

void Hmac(unsigned char* k, unsigned char *message, char *mac) {

    int idx, err;
    hmac_state hmac;
    unsigned char key[KEYSIZE], dst[MAXBLOCKSIZE];
    memcpy(key,k,KEYSIZE);
    unsigned long dstlen;

    /* register SHA-1 */
    register_hash(&sha1_desc);

    /* get index of SHA1 in hash descriptor table */
    idx = find_hash("sha1");

    /* we would make up our symmetric key in "key[]" here */
    /* start the HMAC */
    hmac_init(&hmac, idx, key, 16);

    /* process a few octets */
    hmac_process(&hmac, (const unsigned char*) message, sizeof(message));

    /* get result (presumably to use it somehow...) */
    dstlen = sizeof(dst);
    
    hmac_done(&hmac, dst, &dstlen);

    memcpy(mac, dst, dstlen);

    // cout<<"mac length: "<<dstlen<<" bytes"<<endl;
    // cout<<endl;
    // cout<<mac<<endl;
}
