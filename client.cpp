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
void Hmac(unsigned char* k, unsigned char *message, unsigned char *mac);
void Concat(unsigned char* A, unsigned char* B, unsigned char* AB);


int main (int argc, char** argv)
{
    //makes sure message file is provided
    if(argc < 2){
        cout << "Not enough command line argument provided. Must pass in file name!" << endl;
        return -1;     
    } 

    //  Prepare our context and socket
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REQ);
    std::cout << "Connecting to server…" << std::endl;
    socket.connect ("tcp://localhost:52558");

    //read in plaintexts for encryption
    vector<string> messages = parseMessages(argv[1]);

    unsigned char recv_arr[BUFFER_SIZE];    //use to recieve server mssg
    unsigned char send_arr[BUFFER_SIZE];    //use to send mssg to server 
    unsigned char k_curr[KEYSIZE];          //use to store current key
    unsigned char k_next[KEYSIZE];          //use to store next key
    unsigned char mac_i[KEYSIZE];           //use to store mac 
    unsigned char mac_1_iprev[KEYSIZE];     //use to store prev aggregate mac
    unsigned char mac_1_i[KEYSIZE];         //use to store curr aggregate mac

    
    //initialize initial key
    memcpy(k_next,key,KEYSIZE);
 
    //message counter
    int i = 0;
 
    //begin encrypting N message
    for(auto mssg : messages){

        //copy message into buffer
        memcpy(send_arr,mssg.c_str(),BUFFER_SIZE);
        
        //update key
        memcpy(k_curr,k_next,KEYSIZE);    

        //Encrypt using current iteration key
        Enc(k_curr,send_arr);

        //compute current iteration mac
        Hmac(k_curr,send_arr,mac_i);

        //update aggregate mac
        memcpy(mac_1_iprev,mac_i, KEYSIZE); 

        //concat mac_iprev with current mac
        unsigned char temp[2*KEYSIZE];
        Concat(mac_1_iprev,mac_i,temp);

        //hash to find current aggregate mac
        Hash(temp,mac_1_i);
        
        //Hash key for next iteration
        Hash(k_curr,k_next);


        //send cipher text
        socket.send(send_arr,BUFFER_SIZE);
        //receive acknowledgment
        socket.recv(recv_arr, BUFFER_SIZE);
        //increment message counter
        i++; 

        //print cipher text to console 
        cout << "CIPHERTEXT " << i <<":" << endl;
        cout << send_arr << endl << endl;
        
    }

    cout << "----------------------------------------------------------------------\n" << endl;
    cout << "Final aggregate MAC in integer form: \n" << endl;
    for(int i = 0; i < KEYSIZE; i++){
        cout << (int)mac_1_i[i] << " ";
    }
    cout << endl;

    socket.send(mac_1_i, KEYSIZE);
    socket.recv(recv_arr, BUFFER_SIZE);
    cout << endl << recv_arr << endl;

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

