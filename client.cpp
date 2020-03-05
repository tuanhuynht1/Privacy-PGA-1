//
//  Hello World client in C++
//  Connects REQ socket to tcp://localhost:5555
//  Sends "Hello" to server, expects "World" back
//
#include <zmq.hpp>
#include <string>
#include <sstream>
#include <vector>
#include <string.h>
#include <fstream>
#include <iostream>
#include <tomcrypt.h>

#define KEYSIZE 16
#define BUFFER_SIZE 1024
using namespace std;

//global declaration of secret key and IV
unsigned char key[KEYSIZE] = "123456789012345";
unsigned char IV[KEYSIZE] = "bbcdefhij12345";

vector<string> parseMessages(string file);
int Enc(unsigned char* key, unsigned char* message);


int main (int argc, char** argv)
{
    //  Prepare our context and socket
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REQ);
    std::cout << "Connecting to server…" << std::endl;
    socket.connect ("tcp://localhost:55558");

    //read in plaintexts for encryption
    vector<string> messages = parseMessages(argv[1]);

    unsigned char recv_arr[BUFFER_SIZE];
    unsigned char send_arr[BUFFER_SIZE];

    //begin encrypting each message
    for(auto mssg : messages){
        //copy message into buffer
        memcpy(send_arr,mssg.c_str(),BUFFER_SIZE);

        Enc(key,send_arr);
        cout << send_arr << endl;

        socket.send(send_arr,BUFFER_SIZE);
        socket.recv(recv_arr, BUFFER_SIZE);
        cout << recv_arr << endl;
    }


    

    // socket.send(encrypted_msg, msg_size);
    // socket.recv(recv_arr, 100);


    return 0;
}

vector<string> parseMessages(string file){
    //open file to read
    ifstream ifs(file);
    if (!ifs){
        //file not found
        cout << "File \"" << file << "\" not found!" << endl;
        return {};
    }


    //get argument parameter for N messages
    int n;
    string line;
    getline(ifs,line,'\n');

    n = stoi(line);
    
    vector<string> messages(n);
    for(int i = 0; i < n; i++){
        getline(ifs,line,'\n');
        messages[i] = line;
    }
    return messages;
}

int Enc(unsigned char* key, unsigned char* message)
{
    unsigned char buffer[BUFFER_SIZE];
    memcpy(buffer,message,BUFFER_SIZE);

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
    /* somehow fill buffer than encrypt it */
    if ((err = ctr_encrypt(buffer,         /* plaintext */
                           message,         /* ciphertext */
                           sizeof(buffer), /* length of plaintext pt */
                           &ctr)           /* CTR state */
         ) != CRYPT_OK)
    {
        printf("ctr_encrypt error: %s\n", error_to_string(err));
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

void encrypt_OTP(char* message, char* cipher_text, int keysize)
{
    unsigned char key[keysize];
    pseudo_random_generator(key, keysize);
    
    for(int i = 0; i < keysize; i++)
    {
        cipher_text[i] = message[i] ^ key[i];
    }
}