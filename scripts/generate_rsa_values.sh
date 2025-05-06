#!/bin/bash

# Clean previous files
rm -f private_key.pem public_key.pem message.txt hash.bin signature.bin

# Step 1: Generate RSA private and public keys
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048 > /dev/null 2>&1
openssl rsa -in private_key.pem -pubout -out public_key.pem > /dev/null 2>&1

# Step 2: Prepare message
echo -n "how you doing?" > message.txt

# Step 3: Hash the message
openssl dgst -sha256 -binary message.txt > hash.bin
expectedHash=$(openssl dgst -sha256 message.txt | awk '{ print $2 }')

# Step 4: Sign the hash
openssl rsautl -sign -inkey private_key.pem -in hash.bin -out signature.bin

# Step 5: Extract signature in hex format
signature=$(xxd -p signature.bin | tr -d '\n')

# Step 6: Extract modulus
modulus=$(openssl rsa -in private_key.pem -noout -text | \
          awk '/modulus:/{flag=1;next}/publicExponent/{flag=0}flag' | \
          tr -d ' \n:')

# Step 7: Exponent
exponent="010001"  # 65537 in hex

# Print values 

echo "*******"
echo "const signature = \"0x$signature\";"
echo "const exponent = \"0x$exponent\";"
echo "const modulus = \"0x$modulus\";"
echo "const expectedHash = \"0x$expectedHash\";"
echo "*******"
