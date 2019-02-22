#include "secp256k1.h"
#include "keccak256.h"
#include <iostream>
#include <fstream>
#include <random>
#include <chrono>
#include <unistd.h> // fork

// Only for debugging; testing code execution time
#define TIME_POINT       std::chrono::high_resolution_clock::time_point
#define NOW              std::chrono::high_resolution_clock::now()
#define DIFFERENCE(a, b) std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count()
#define SHORTEN(a)       (float)a/(float)1000

char* PrivateKeyToString(const uint8_t* privateKey){
  char* privateKeyString = new char[65];
  snprintf(
    privateKeyString, 65,
    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
    privateKey[0],  privateKey[1],  privateKey[2],  privateKey[3],  privateKey[4],  privateKey[5],  privateKey[6],  privateKey[7],
    privateKey[8],  privateKey[9],  privateKey[10], privateKey[11], privateKey[12], privateKey[13], privateKey[14], privateKey[15],
    privateKey[16], privateKey[17], privateKey[18], privateKey[19], privateKey[20], privateKey[21], privateKey[22], privateKey[23],
    privateKey[24], privateKey[25], privateKey[26], privateKey[27], privateKey[28], privateKey[29], privateKey[30], privateKey[31]
    );
  return privateKeyString;
}

void int_to_bin_print(uint32_t number){
  int SIZE = 64;

  char binaryNumber[SIZE+1];
  int i;
  for(i = SIZE-1; i >= 0; --i){
    binaryNumber[i] = (number & 1) ? '1' : '0';
    number >>= 1;
  }
  binaryNumber[SIZE] = '\0';
  printf("%s\n", binaryNumber);
}

uint8_t* GenerateRandom(void){
  // char hexdigit[17] = "0123456789abcdef";
  // hexdigit[16] = '\0';

  // char* buf = new char[5];

  // unsigned char a = (unsigned char) rand();
  // unsigned char b = (unsigned char) rand();
  // unsigned char c = (unsigned char) rand();
  // unsigned char d = (unsigned char) rand();

  // std::cout << "|" << a << "|\n";
  // std::cout << "|" << b << "|\n";
  // std::cout << "|" << c << "|\n";
  // std::cout << "|" << d << "|\n";

  uint8_t* privateKey = new uint8_t[33];
  privateKey[32] = '\0';
  for(int i = 0; i < 32; i++){
    privateKey[i] = (unsigned char) rand();
  }

  // for(int i = 0; i < 4; ++i)
  //   buf[i] = hexdigit[rand() % sizeof hexdigit];
  // buf[4] = '\0';

  // std::cout << buf << "\n";

  return privateKey;

  std::random_device rd;

  // Random number generator
  std::default_random_engine engine;
  engine.seed(std::chrono::system_clock::now().time_since_epoch().count());

  // Distribution on which to apply the generator
  std::uniform_int_distribution<uint64_t> distribution(0, 0xFFFFFFFFFFFFFFFF);

  std::cout << "Size: " << sizeof(uint64_t) << "\n";

  for (int i = 0; i < 10; i++) {
      uint64_t result = distribution(engine);
      int_to_bin_print(result);
      // std::cout << distribution(engine) << "\n";
  }
}

int main(){
  int TOTAL_AMOUNT_OF_JOBS = 36;

  TIME_POINT t1 = NOW;

  int i = 1;
  for(; i < TOTAL_AMOUNT_OF_JOBS; i++){
    if(fork() == 0)
      break;
  }

  srand((unsigned)time(0) + i);

  // for(int i = 0; i < 1000000; i++){
  while(true){
    uint8_t* privateKey_ = GenerateRandom();
    char* publicKey_ = Wrapper(privateKey_);
    char* address_ = PublicKeyToAddress(publicKey_);

    if(address_[2]  == '0' &&
       address_[3]  == '0' &&
       address_[4]  == '0' &&
       address_[5]  == '0' &&
       address_[6]  == '0' &&
       address_[7]  == '0' &&
       address_[8]  == '0'/* &&
       address_[9]  == '0'*/){
      char* privateKeyString_ = PrivateKeyToString(privateKey_);

      std::ofstream outfile;
      outfile.open("addresses.txt", std::ios_base::app);
      outfile << address_ << "," << privateKeyString_ << "\n";
      std::cout << address_ << "," << privateKeyString_ << "\n";
      delete[] privateKeyString_;
    }

    delete[] privateKey_;
    delete[] publicKey_;
    delete[] address_;
  }

  TIME_POINT t2 = NOW;
  std::cout << "DURATION IN SECONDS: " << SHORTEN(DIFFERENCE(t1, t2)) << "\n";
  return 0;
}

/* Private Key
 * abcdef1203405600789001112233aabbcc24680abcdef00001234567890abcde
 *
 * Public Key
 * 64c9992d70d56cf60383b86dcba395ee0ccdb780b13d1b52803b010ae62574b68ebc46f0b25acf3721da182a180b985500669ec8541244752ec1331ea61aacee
 *
 * Keccak256 Hash
 * 3bb89452fe5544e057767a22e7b8a14e8338963e64fb146cd22746b543d339e8
 *
 * Address
 * 0xe7B8a14E8338963E64fB146cd22746B543D339e8
 */
