#include <tomcrypt.h>
#include <bits/stdc++.h>

using namespace std;

void pseudo_random_generator(unsigned char *arr, int keysize)
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

int suggest_key_size()
{
    int keysize, err;
    /* now given a 20 byte key what keysize does Twofish want to use? */
    keysize = 20;
    if ((err = twofish_keysize(&keysize)) != CRYPT_OK)
    {
        printf("Error getting key size: %s\n", error_to_string(err));
        return -1;
    }
    printf("Twofish suggested a key size of %d bytes\n", keysize);
    return 0;
}

int ctr_encrypt()
{
    unsigned char key[16] = "abcdefhij12345", IV[16] = "bbcdefhij12345", buffer[512] = "hello world Alice Bob EVE";

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
                           buffer,         /* ciphertext */
                           sizeof(buffer), /* length of plaintext pt */
                           &ctr)           /* CTR state */
         ) != CRYPT_OK)
    {
        printf("ctr_encrypt error: %s\n", error_to_string(err));
        return -1;
    }
    cout << buffer << endl;
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
                           buffer,         /* plaintext */
                           sizeof(buffer), /* length of plaintext */
                           &ctr)           /* CTR state */
         ) != CRYPT_OK)
    {
        printf("ctr_decrypt error: %s\n", error_to_string(err));
        return -1;
    }
    cout << buffer << endl;
    /* terminate the stream */
    if ((err = ctr_done(&ctr)) != CRYPT_OK)
    {
        printf("ctr_done error: %s\n", error_to_string(err));
        return -1;
    }
    /* clear up and return */
    zeromem(key, sizeof(key));
    zeromem(&ctr, sizeof(ctr));
    return 0;
}

void compute_hmac(char *message, char *mac)
{
    int idx, err;
    hmac_state hmac;
    unsigned char key[16]="123456123456xyx", dst[MAXBLOCKSIZE];
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

    cout<<"mac length: "<<dstlen<<" bytes"<<endl;
    cout<<endl;
    cout<<mac<<endl;
} 

void encrypt_OTP(char* message, char* cipher, int keysize)
{
    unsigned char key[keysize];
    pseudo_random_generator(key, keysize);
    for(int i = 0; i < keysize; i++)
    {
        cipher[i] = message[i] ^ key[i];
    }
}

void decrypt_OTP(char* cipher, char* plain_text, int keysize)
{
    unsigned char key[keysize];
    pseudo_random_generator(key, keysize);
    for(int i = 0; i < keysize; i++)
    {
        plain_text[i] = cipher[i] ^ key[i];
    }
}



int main(void)
{
    int keysize = 20;
    unsigned char key[keysize];
    char message[] = "ALICE BOB EVE";
    char cipher_text[keysize];
    encrypt_OTP(message, cipher_text, keysize);
    cout<<cipher_text<<endl;
    for(int i= 0;i < keysize; i++)
    {
        int k;
        k = cipher_text[i];
        cout<<k;
    }
    cout<<endl;
    char plain_text[keysize];
    decrypt_OTP(cipher_text, plain_text, keysize);
    cout<<plain_text<<endl;
    char mac[keysize];
    compute_hmac(message, mac);
    cout<<mac<<endl;
    return 0;
}
