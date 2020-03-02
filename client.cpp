//
//  Hello World client in C++
//  Connects REQ socket to tcp://localhost:5555
//  Sends "Hello" to server, expects "World" back
//
#include <zmq.hpp>
#include <string>
#include <iostream>

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

void encrypt_OTP(char* message, char* cipher_text, int keysize)
{
    unsigned char key[keysize];
    pseudo_random_generator(key, keysize);
    
    for(int i = 0; i < keysize; i++)
    {
        cipher_text[i] = message[i] ^ key[i];
    }
}

int main ()
{
    //  Prepare our context and socket
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REQ);

    std::cout << "Connecting to server…" << std::endl;
    socket.connect ("tcp://localhost:55558");

    char send_arr[] = "Hello from client";

    int msg_size = sizeof(send_arr);
    char encrypted_msg[msg_size];

    encrypt_OTP(send_arr, encrypted_msg, msg_size);

    socket.send(encrypted_msg, msg_size);

    cout<<"Successfully sent"<<endl;

    char recv_arr[100];

    socket.recv(recv_arr, 100);

    cout<<recv_arr<<endl;

    return 0;
}