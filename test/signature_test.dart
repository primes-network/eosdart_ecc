import 'dart:convert';
import 'dart:typed_data';

import 'package:eosdart_ecc/eosdart_ecc.dart';
import 'package:test/test.dart';
import 'package:crypto/crypto.dart';

void main() {
  group('EOS signature tests', () {
    test('Construct EOS signature from string', () {
      String sigStr =
          'SIG_K1_Kg417TSLuhzSpU2bGa21kD1UNaTfAZSCcKmKpZ6fnx3Nqu22gzG3ND4Twur7bzX8oS1J91JvV4rMJcFycGqFBSaY2SJcEQ';
      EOSSignature signature = EOSSignature.fromString(sigStr);
      print(signature);

      expect(sigStr, signature.toString());
    });

    test('Sign the hash using private key', () {
      EOSPrivateKey privateKey = EOSPrivateKey.fromString(
          '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3');
      EOSPublicKey publicKey = privateKey.toEOSPublicKey();

      String data = 'data';
      Uint8List hashData = sha256.convert(utf8.encode(data)).bytes;
      EOSSignature signature = privateKey.signHash(hashData);

      expect(
          'SIG_K1_Kg417TSLuhzSpU2bGa21kD1UNaTfAZSCcKmKpZ6fnx3Nqu22gzG3ND4Twur7bzX8oS1J91JvV4rMJcFycGqFBSaY2SJcEQ',
          signature.toString());
      expect(true, signature.verifyHash(hashData, publicKey));
    });
  });
}
