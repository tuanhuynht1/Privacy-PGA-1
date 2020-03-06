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
void Hash(unsigned char* message, unsigned char* hash);


int main (int argc, char** argv)
{
    //makes sure message file is provided
    if(argc < 2){
        cout << "NOOB" << endl;
        return -1;     
    } 

    //  Prepare our context and socket
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REQ);
    std::cout << "Connecting to server…" << std::endl;
    socket.connect ("tcp://localhost:52558");

    //read in plaintexts for encryption
    vector<string> messages = parseMessages(argv[1]);

    unsigned char recv_arr[BUFFER_SIZE];
    unsigned char send_arr[BUFFER_SIZE];

    unsigned char k_curr[KEYSIZE];
    unsigned char k_next[KEYSIZE];
    
    //initialize initial key
    memcpy(k_next,key,KEYSIZE);     

    //begin encrypting each message
    for(auto mssg : messages){

        //copy message into buffer
        memcpy(send_arr,mssg.c_str(),BUFFER_SIZE);
        
        //update key
        memcpy(k_curr,k_next,KEYSIZE);     

        //Encrypt using current iteration key
        Enc(k_curr,send_arr);
        
        //Hash key
        Hash(k_curr,k_next);



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

void Hash(unsigned char* message, unsigned char* hash){
    hash_state md;
    md5_init(&md);
    md5_process(&md, message, KEYSIZE);
    md5_done(&md, hash);
}

