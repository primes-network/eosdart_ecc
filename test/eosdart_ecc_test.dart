import 'package:eosdart_ecc/eosdart_ecc.dart';
import 'package:test/test.dart';

void main() {
  group('EOS Key tests', () {
    test('Construct EOS public key from string', () {
      EOSPublicKey publicKey = EOSPublicKey.fromString(
          'EOS8Qi58kbERkTJC7A4gabxYU4SbrAxStJHacoke4sf6AvJyEDZXj');
      print(publicKey);

      expect('EOS8Qi58kbERkTJC7A4gabxYU4SbrAxStJHacoke4sf6AvJyEDZXj',
          publicKey.toString());
    });

    test('Construct EOS public key from string PUB_K1 format', () {
      EOSPublicKey publicKey = EOSPublicKey.fromString(
          'PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX');
      print(publicKey);
    });

    test('Construct EOS private key from string', () {
      // common private key
      EOSPrivateKey privateKey = EOSPrivateKey.fromString(
          '5J9b3xMkbvcT6gYv2EpQ8FD4ZBjgypuNKwE1jxkd7Wd1DYzhk88');
      expect('EOS8Qi58kbERkTJC7A4gabxYU4SbrAxStJHacoke4sf6AvJyEDZXj',
          privateKey.toEOSPublicKey().toString());
      expect('5J9b3xMkbvcT6gYv2EpQ8FD4ZBjgypuNKwE1jxkd7Wd1DYzhk88',
          privateKey.toString());
    });

    test('Invalid EOS private key', () {
      try {
        EOSPrivateKey.fromString(
            '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjsm');
        fail('Should be invalid private key');
      } on InvalidKey {} catch (e) {
        fail('Should throw InvalidKey exception');
      }
    });

    test('Construct random EOS private key from seed', () {
      EOSPrivateKey privateKey = EOSPrivateKey.fromSeed('abc');
      print(privateKey);
      print(privateKey.toEOSPublicKey());

      EOSPrivateKey privateKey2 =
          EOSPrivateKey.fromString(privateKey.toString());
      expect(privateKey.toEOSPublicKey().toString(),
          privateKey2.toEOSPublicKey().toString());
    });

    test('Construct random EOS private key', () {
      EOSPrivateKey privateKey = EOSPrivateKey.fromRandom();

      print(privateKey);
      print(privateKey.toEOSPublicKey());

      EOSPrivateKey privateKey2 =
          EOSPrivateKey.fromString(privateKey.toString());
      expect(privateKey.toEOSPublicKey().toString(),
          privateKey2.toEOSPublicKey().toString());
    });

    test('Construct EOS private key from string in PVT format', () {
      // PVT private key
      EOSPrivateKey privateKey2 = EOSPrivateKey.fromString(
          'PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd');
      print(privateKey2);
    });

    test('Construct EOS private key from string with compress flag', () {
      // Compressed private key
      EOSPrivateKey privateKey3 = EOSPrivateKey.fromString(
          'L5TCkLizyYqjvKSy6jg1XM3Lc4uTDwwvHS2BYatyXSyoS8T5kC2z');
      print(privateKey3);
    });
  });
}
