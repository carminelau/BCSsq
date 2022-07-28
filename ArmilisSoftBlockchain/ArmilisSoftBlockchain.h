/*

  ArmilisSoftBlockchain.h - Library for signing data with ED25519 software library and write it to blockchain .

  Created by Ludovico Binda @ ARMILIS.com, MAy, 2022.

  Hashing functions are from: 2015 Southern Storm Software, Pty Ltd. (see details in Crypto.h)

*/


#ifndef ArmilisSoftBlockchain_h

#define ArmilisSoftBlockchain_h


#include "Arduino.h"
#include "Ed25519.h"
#include "SHA256.h"









class ArmilisSoftBlockchain

{

  public:

    ArmilisSoftBlockchain();

    bool load_key_hardcoded(String krl, uint8_t keyinput[32]);

    String get_public_key();

    String create_certification_packet(String hrt, String to_hash, String tdr);




  private:


    String _pubkey;
    uint8_t _signature[64];
    String _rndsig;
    uint8_t _hash[32];
    //uint8_t _rndhash[32];
    uint8_t _privkey[32];
    uint8_t _publicKey[32];
    String _krl;
    bool _iskeyloaded;

    String _Hex8ToString(uint8_t *data, uint8_t length);
    String _random_string(int lenght);
    String _string_hash(String tosign);
    String _rndAuthString();
    String _ploadentropyString();
    String _string_hash_and_sign(String input);
    String _string_sign(String input);

};


#endif
