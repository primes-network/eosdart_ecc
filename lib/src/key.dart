import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';

import 'package:bs58check/bs58check.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/pointycastle.dart' as pointycastle;
import 'package:pointycastle/src/utils.dart';
import 'package:crypto/crypto.dart';
import "package:pointycastle/ecc/curves/secp256k1.dart";

import './exception.dart';
import './key_base.dart';

/// EOS Public Key
class EOSPublicKey extends EOSKey {
  /// Construct EOS public key from string
  EOSPublicKey.fromString(String keyStr) {
    RegExp publicRegex = RegExp(r"^PUB_([A-Za-z0-9]+)_([A-Za-z0-9]+)",
        caseSensitive: true, multiLine: false);
    Iterable<Match> match = publicRegex.allMatches(keyStr);

    if (match.length == 0) {
      RegExp eosRegex = RegExp(r"^EOS", caseSensitive: true, multiLine: false);
      if (!eosRegex.hasMatch(keyStr)) {
        throw InvalidKey("No leading EOS");
      }
      String publicKeyStr = keyStr.substring(3);
      key = EOSKey.decodeKey(publicKeyStr, keyType);
    } else if (match.length == 1) {
      Match m = match.first;
      keyType = m.group(1);
      key = EOSKey.decodeKey(m.group(2), keyType);
    } else {
      throw InvalidKey('Invalid public key format');
    }
  }

  String toString() {
    return 'EOS' + EOSKey.encodeKey(key, keyType);
  }
}

/// EOS Private Key
class EOSPrivateKey extends EOSKey {
  String format;

  /// Default constructor from the key buffer itself
  EOSPrivateKey(Uint8List key) : super(key);

  /// Construct the private key from string
  /// It can come from WIF format for PVT format
  EOSPrivateKey.fromString(String keyStr) {
    RegExp privateRegex = RegExp(r"^PVT_([A-Za-z0-9]+)_([A-Za-z0-9]+)",
        caseSensitive: true, multiLine: false);
    Iterable<Match> match = privateRegex.allMatches(keyStr);

    if (match.length == 0) {
      format = 'WIF';
      keyType = 'K1';
      // WIF
      Uint8List keyWLeadingVersion = EOSKey.decodeKey(keyStr, EOSKey.SHA256X2);
      int version = keyWLeadingVersion.first;
      if (EOSKey.VERSION != version) {
        throw InvalidKey("version mismatch");
      }

      key = keyWLeadingVersion.sublist(1, keyWLeadingVersion.length);
      if (key.length == 33 && key.elementAt(32) == 1) {
        key = key.sublist(0, 32);
      }

      if (key.length != 32) {
        throw InvalidKey('Expecting 32 bytes, got ${key.length}');
      }
    } else if (match.length == 1) {
      format = 'PVT';
      Match m = match.first;
      keyType = m.group(1);
      key = EOSKey.decodeKey(m.group(2), keyType);
    } else {
      throw InvalidKey('Invalid Private Key format');
    }
  }

  /// Generate EOS private key from seed. Please note: This is not random!
  /// For the given seed, the generated key would always be the same
  factory EOSPrivateKey.fromSeed(String seed) {
    Digest s = sha256.convert(utf8.encode(seed));
    return EOSPrivateKey(s.bytes);
  }

  /// Generate the random EOS private key
  factory EOSPrivateKey.fromRandom() {
    final int randomLimit = 1 << 32;
    Random randomGenerator;
    try {
      randomGenerator = Random.secure();
    } catch (e) {
      randomGenerator = new Random();
    }

    int randomInt1 = randomGenerator.nextInt(randomLimit);
    Uint8List entropy1 = encodeBigInt(BigInt.from(randomInt1));

    int randomInt2 = randomGenerator.nextInt(randomLimit);
    Uint8List entropy2 = encodeBigInt(BigInt.from(randomInt2));

    int randomInt3 = randomGenerator.nextInt(randomLimit);
    Uint8List entropy3 = encodeBigInt(BigInt.from(randomInt3));

    List<int> entropy = entropy1.toList();
    entropy.addAll(entropy2);
    entropy.addAll(entropy3);
    Uint8List randomKey = Uint8List.fromList(entropy);
    Digest d = sha256.convert(randomKey);
    return EOSPrivateKey(d.bytes);
  }

  /// Check if the private key is WIF format
  bool isWIF() => this.format == 'WIF';

  /// Get the public key string from this private key
  String toEOSPublicKey() {
    BigInt privateKeyNum = decodeBigInt(this.key);
    pointycastle.ECPoint ecPoint = ECCurve_secp256k1().G * privateKeyNum;
    Uint8List encodedBuffer = ecPoint.getEncoded(true);

    Uint8List checksum = RIPEMD160Digest().process(encodedBuffer);
    checksum = checksum.sublist(0, 4);

    Uint8List key = EOSKey.concat(encodedBuffer, checksum);
    String publicKey = 'EOS' + base58.encode(key);

    return publicKey;
  }

  String toString() {
    List<int> version = List<int>();
    version.add(EOSKey.VERSION);
    Uint8List keyWLeadingVersion =
        EOSKey.concat(Uint8List.fromList(version), this.key);

    return EOSKey.encodeKey(keyWLeadingVersion, EOSKey.SHA256X2);
  }
}
