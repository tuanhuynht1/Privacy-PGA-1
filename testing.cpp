#include <tomcrypt.h>
#include <bits/stdc++.h>
#include <cstring>
#include <sstream>
#include <vector>
#include <string.h>
#include <fstream>
#include <iostream>

#define KEYSIZE 16
#define BUFFER_SIZE 1024
using namespace std;

unsigned char key[KEYSIZE] = "123456789012345";
unsigned char IV[KEYSIZE] = "bbcdefhij12345";

int Enc(unsigned char* key, unsigned char* message);
int Dec(unsigned char* key, unsigned char* cipher);

int main(int argc, char** argv){

    //open file to read
    ifstream ifs(argv[1]);
    if (!ifs){
        //file not found
        cout << "File \"" << argv[1] << "\" not found!" << endl;
        return -1;
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


    for(int i = 0; i < n; i++)
    {
        unsigned char mssg[BUFFER_SIZE];
        memcpy(mssg,messages[i].c_str(),BUFFER_SIZE);
        Enc(key,mssg);
        cout << mssg << endl << "---------------------------------------------------\n";
        Dec(key,mssg);
        cout << mssg << endl << "---------------------------------------------------\n";
    }	

	return 0;
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



















