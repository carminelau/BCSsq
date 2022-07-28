/*

  ArmilisSoftBlockchain.h - Library for signing data with ED25519 software library and write it to blockchain .

  Created by Ludovico Binda @ ARMILIS.com, MAy, 2022.

  Hashing functions are from: 2015 Southern Storm Software, Pty Ltd. (see details in Crypto.h)

*/

#include "ArmilisSoftBlockchain.h"
#include "Arduino.h"
#include "Ed25519.h"
#include "SHA256.h"


/**********************PUBLIC FUNCTIONS*********************/

// CONSTRUCTOR
ArmilisSoftBlockchain::ArmilisSoftBlockchain()
{



}




// SETUP
bool ArmilisSoftBlockchain::load_key_hardcoded(String krl, uint8_t keyinput[32])
{

if (_iskeyloaded){return false;} //if a key is already loaded return False - you need another cert obj if you want to use another key

int i = 0;
while(i<32){
  _privkey[i] = keyinput[i];
  i++;
}

Ed25519::derivePublicKey(_publicKey, _privkey);
_iskeyloaded=true;
return true;

}







//Return Public key as a string. TODO: As a String or C string?! TODO: HOW TO CALL THE HEXTOTOSTRING FOR MERE?

String ArmilisSoftBlockchain::get_public_key()
{
//what should it look into?
 return _Hex8ToString(_publicKey, 32);
}






//Create a Certification Request pakcet
String ArmilisSoftBlockchain::create_certification_packet(String hrt, String to_hash, String tdr)
{
  String relToSign = "";
  String messageAPI = "{\"payload\":{";


  if (hrt.length()>0){    messageAPI = messageAPI + "\"hrt\":\"";
                          messageAPI = messageAPI + hrt;
                          messageAPI = messageAPI + "\",";
                          relToSign = relToSign + hrt;
                         }




  if (to_hash.length()>0){String _hsh = "";
                         _hsh = _string_hash(to_hash); // TODO: SHOULD I SPECIFY ArmilisSoftBlockchain:?!?!
                          messageAPI = messageAPI + "\"hsh\":\"";
                          messageAPI = messageAPI + _hsh;
                          messageAPI = messageAPI + "\",";
                          relToSign = relToSign + _hsh;
                         }




  if (_krl.length()>0){    messageAPI = messageAPI + "\"krl\":\"";
                          messageAPI = messageAPI + _krl;
                          messageAPI = messageAPI + "\",";
                          relToSign = relToSign + _krl;
                         }



  if (tdr.length()>0){    messageAPI = messageAPI + "\"tdr\":\"";
                          messageAPI = messageAPI + tdr;
                          messageAPI = messageAPI + "\",";
                          relToSign = relToSign + tdr;
                         }




  messageAPI = messageAPI +"\"sig\":\"";
  messageAPI = messageAPI +_string_hash_and_sign(relToSign);
  messageAPI = messageAPI +"\"},";



  String auts = _rndAuthString();
  messageAPI = messageAPI + "\"authentication\":{\"rnd\":\"";
  messageAPI = messageAPI + auts;
  messageAPI = messageAPI +"\",\"pbk\":\"";
  messageAPI = messageAPI + _Hex8ToString(_publicKey, 32);
  messageAPI = messageAPI +("\",\"rnds\":\"");
  messageAPI = messageAPI + _string_sign(auts);
  messageAPI = messageAPI +"\"}}";


  return messageAPI;

}




/****************PRIVATE FUNCTIONS*****************/


String ArmilisSoftBlockchain::_Hex8ToString(uint8_t *data, uint8_t length)
{
     char tmp[length*2+1];
     byte first;
     byte second;
     for (int i=0; i<length; i++) {
           first = (data[i] >> 4) & 0x0f;
           second = data[i] & 0x0f;
           // base for converting single digit numbers to ASCII is 48
           // base for 10-16 to become lower-case characters a-f is 87
           // note: difference is 39
           tmp[i*2] = first+48;
           tmp[i*2+1] = second+48;
           if (first > 9) tmp[i*2] += 39;
           if (second > 9) tmp[i*2+1] += 39;
     }
     tmp[length*2] = 0;
      String pippo = String(tmp);
      return pippo;
}







String ArmilisSoftBlockchain::_random_string(int lenght){
String entropy="";
int i = 0;
while(i<lenght){
  entropy=entropy + (char)(random(97,122));
  i++;};
  return entropy;
}








String ArmilisSoftBlockchain::_string_hash(String tosign){

uint8_t hash[32];
// 1.1 Converting the message to a byte array
unsigned int mlen = tosign.length();//rememeber we don't sign the trailing \n but the getbytes need it, hence the two "+1" in the following lines
uint8_t mbytes[mlen+1];
tosign.getBytes(mbytes, mlen+1);

// 1.2 hashing it
SHA256 sha256;
sha256.update(mbytes,mlen);
sha256.finalize(hash,32);
sha256.~SHA256();

return _Hex8ToString(hash,32);

}







String ArmilisSoftBlockchain::_string_hash_and_sign(String tosign) {

String signature;
unsigned int mlen = tosign.length();//rememeber we don't sign the trailing \n but the getbytes need it, hence the two "+1" in the following lines
uint8_t mbytes[mlen+1];
tosign.getBytes(mbytes, mlen+1);

// 1.2 hashing it
SHA256 sha256;
sha256.update(mbytes,mlen);
sha256.finalize(_hash,32);
sha256.~SHA256();


String stringpd=_Hex8ToString(_hash,32);
int msglenpd = stringpd.length();//rememeber we don't sign the trailing \n but the getbytes need it, hence the two "+1" in the following lines
uint8_t messagebytespd[msglenpd+1];
stringpd.getBytes(messagebytespd, msglenpd+1);

Ed25519::sign(_signature, _privkey, _publicKey,messagebytespd,msglenpd);


return _Hex8ToString(_signature, 64);


}





String ArmilisSoftBlockchain::_string_sign(String tosign) {
/*
String signature;
unsigned int mlen = tosign.length();//rememeber we don't sign the trailing \n but the getbytes need it, hence the two "+1" in the following lines
uint8_t mbytes[mlen+1];
tosign.getBytes(mbytes, mlen+1);

// 1.2 hashing it
SHA256 sha256;
sha256.update(mbytes,mlen);
sha256.finalize(_hash,32);
sha256.~SHA256();
*/

String stringpd=tosign;
int msglenpd = stringpd.length();//rememeber we don't sign the trailing \n but the getbytes need it, hence the two "+1" in the following lines
uint8_t messagebytespd[msglenpd+1];
stringpd.getBytes(messagebytespd, msglenpd+1);

Ed25519::sign(_signature, _privkey, _publicKey,messagebytespd,msglenpd);


return _Hex8ToString(_signature, 64);


}


// candidate: static void Ed25519::sign(uint8_t*, const uint8_t*, const uint8_t*, const void*, size_t)




String ArmilisSoftBlockchain::_rndAuthString(){

String authrnd="ESP";
 int i = 0;
while(i<15){
  authrnd=authrnd + (char)random(97,122);
  i++;}

return authrnd;
}

String ArmilisSoftBlockchain::_ploadentropyString(){

String authrnd="";
 int i = 0;
while(i<9){
  authrnd=authrnd + (char)random(97,122);
  i++;}

return authrnd;
}
