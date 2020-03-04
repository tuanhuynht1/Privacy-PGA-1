#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>

#include <tomcrypt.h>

using namespace std;

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

int main () {
    //  Prepare our context and socket
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REP);
    socket.bind ("tcp://*:55558");


    while (true) {
        char recv_arr[100];

        //  Wait for next request from client
        socket.recv(recv_arr, 100);
        cout<<"before decryption "<<recv_arr<<endl;
        char decrypted_text[sizeof(recv_arr)];

        decrypt_OTP(recv_arr, decrypted_text, sizeof(recv_arr));

        cout<<"after decryption "<<decrypted_text<<endl;


        //char send_arr[] = "successfully received your message";
        socket.send("OK", 100);
    }
    return 0;
}