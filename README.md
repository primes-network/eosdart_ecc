# Elliptic curve cryptography (ECC) in Dart

Elliptic curve cryptography lib for EOS based blockchain in Dart lang.

## Usage

A simple usage example:

```dart
import 'package:eosdart_ecc/eosdart_ecc.dart';

main() {
  // Construct the EOS private key from string
  EOSPrivateKey privateKey = EOSPrivateKey.fromString(
      '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3');

  // Get the related EOS public key
  EOSPublicKey publicKey = privateKey.toEOSPublicKey();
  // Print the EOS public key
  print(publicKey.toString());

  // Going to sign the data
  String data = 'data';
  
  // Sign
  EOSSignature signature = privateKey.sign(data);
  // Print the EOS signature
  print(signature.toString());

  // Verify the data using the signature
  signature.verify(data, publicKey);
}
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

## References

eosjs-ecc: https://github.com/EOSIO/eosjs-ecc

[tracker]: https://github.com/primes-network/eosdart_ecc/issues
