
/***************************************************

This example for the ARMILIS soft blockchain library helps you create singed packets to send ARMILIS to create blockchain record.

The reference API is a POST to https://serving.armilis.com/api/v0.2/bcStore

****************************************************/


// Including the needed library
#include <ArmilisSoftBlockchain.h>


// Creating an istance of the certificator object
ArmilisSoftBlockchain certificator;


/* Optional paramemeter, the URL where you publisk a finle containing the public key of the sensor in this format:

-----BEGIN PUBLIC KEY-----
E4F5415546FB208F871968C7E60FB4958447A26A17898F26796FB03108A4051D
-----END PUBLIC KEY-----
Example mock link: https://EXAMPLE.armilis.com/pubkeys/poc_key.txt
This enables the corrlation of records with your identity thru a SSl certificate */
String key_url = "";


// Private Key. NOTE: THE UNSECURED, HARDCODED PRIVATE KEY IS ***EXCLUSIVELY*** FOR TESTING
static uint8_t privateKey[32] = {161,82,89,147,251,4,62,218,95,37,167,226,227,148,204,131,188,21,50,149,173,23,138,40,89,134,75,57,233,83,242,62};


/* HOW TO USE THE VIRTUAL DRAWER: SET IT AS A HIGH ENTROPY STRING MEANINGFUL TO YOU (ES: "INTERIORTEMP_813749182791287391")
It will be converted to a blockchain address and the records concatenated: see all them at (example link with example string) this link  OR with our API for m2m use.
https://serving.armilis.com/html/v0.2/listtagoprets?addr=INTERIORTEMP_813749182791287391 */
String digitalTwin = "";





void setup() {

  Serial.begin(115200);

  delay(6000); // so you can open the serial monitor :P


  if(!certificator.load_key_hardcoded("",privateKey)){Serial.println("Key loading failure"); while(1);}  //We load the private key

  Serial.println("This is the public key derived from the private one from the slot 0 of the ATECC chip on this board - forward to ARMILS to get an account");
  Serial.println(certificator.get_public_key());

  }





void loop() {

  delay(10000);

  //DEFINING THE INPUT TO BE CERTIFIED:  
  //A cleartext, stored as-is
  String cleartext = "imitation is the best form of flattery";  
  
  //A string that will be hashed, with the hash subsequently included in blockchain - empty string if none
  String hash_to_blockchain = "";


  // Creating and printign the certification packet - ready to be transmitted to Armilis.
  String packet = certificator.create_certification_packet(cleartext, hash_to_blockchain, digitalTwin);
  

  Serial.println("Send this write request packet to Armilis:");
  Serial.println(packet);


  } 
