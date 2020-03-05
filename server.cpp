#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>

#include <tomcrypt.h>

#define KEYSIZE 16
#define BUFFER_SIZE 1024
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

    int i = 0;

    cout << "SERVER ONLINE" << endl;

    while (true) {
        char recv_arr[BUFFER_SIZE];

        //  Wait for next request from client
        socket.recv(recv_arr, BUFFER_SIZE);
        cout << recv_arr << endl;
        socket.send(to_string(i).c_str(), BUFFER_SIZE);
        i++;

    }
    return 0;
}