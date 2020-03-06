#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <sstream>
#include <tomcrypt.h>

#define KEYSIZE 16
#define BUFFER_SIZE 1024
using namespace std;

unsigned char key[KEYSIZE] = "123456789012345";
unsigned char IV[KEYSIZE] = "bbcdefhij12345";

int Dec(unsigned char* key, unsigned char* cipher);
void Hash(unsigned char* message, unsigned char* hash);
void Hmac(unsigned char* k, unsigned char *message, unsigned char *mac);
void Concat(unsigned char* A,  unsigned char* B,  unsigned char* AB);

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
    unsigned char mac_i[KEYSIZE];           //use to store mac 
    unsigned char mac_1_iprev[KEYSIZE];     //use to store prev aggregate mac
    unsigned char mac_1_i[KEYSIZE];
    
    //initialize initial key
    memcpy(k_next,key,KEYSIZE);


    while (i<100) {


        //  Wait for next request from client
        socket.recv(recv_arr, BUFFER_SIZE);
        
        //update key
        memcpy(k_curr,k_next,KEYSIZE);

        //compute mac_i of cipher
        Hmac(k_curr,recv_arr,mac_i);

        //update aggregate mac
        memcpy(mac_1_iprev,mac_i, KEYSIZE); 

        //concat mac_iprev with current mac
        unsigned char temp[2*KEYSIZE];
        Concat(mac_1_iprev,mac_i,temp);

        //hash to find current aggregate mac
        Hash(temp,mac_1_i);

        // cout << recv_arr << endl;
        Dec(k_curr,recv_arr);
        // cout << recv_arr << endl;

        //hash key
        Hash(k_curr,k_next);

        
        socket.send("Mesasge received", BUFFER_SIZE);
        i++;

    }

    for(int i = 0; i < KEYSIZE; i++){
        cout << (int)mac_1_i[i] << " ";
    }
    cout << endl;

    //saves final mac for verification
    unsigned char client_mac[KEYSIZE];
    socket.recv(client_mac,KEYSIZE);

    //verifies server computed mac with client's mac
    bool valid = true;
    for(int i = 0; i < KEYSIZE; i++){
        int x = mac_1_i[i], y = client_mac[i];
        if (x != y){
            valid = false;
            break;
        }
    }

    if(valid){
        cout << "Write to file" << endl;
        socket.send("Good",BUFFER_SIZE);
    }
    else{
        // cout << client_mac << endl;
        socket.send("Bad",BUFFER_SIZE);
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

void Hmac(unsigned char* k, unsigned char *message, unsigned char *mac) {

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

void Concat(unsigned char* A,  unsigned char* B,  unsigned char* AB){
    for(int i = 0; i < KEYSIZE; i++){
        AB[i] = A[i];
    }
    for(int i = KEYSIZE; i < 2*KEYSIZE; i++){
        AB[i] = A[i];
    }
}

