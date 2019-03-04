import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';

import './exception.dart';
import 'package:bs58check/bs58check.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/pointycastle.dart' as pointycastle;
import 'package:pointycastle/src/utils.dart';
import 'package:crypto/crypto.dart';
import "package:pointycastle/ecc/curves/secp256k1.dart";

/// abstract EOS Key
abstract class EOSKey {
  /// Decode key from string format
  Uint8List decodeKey(String keyStr, [String keyType]) {
    Uint8List buffer = base58.decode(keyStr);

    print(buffer.length);
    Uint8List checksum = buffer.sublist(buffer.length - 4, buffer.length);
    print(checksum);
    Uint8List key = buffer.sublist(0, buffer.length - 4);
    print(key);

    Uint8List newChecksum;
    if (keyType == 'sha256x2') {
      newChecksum = _sha256x2(key).sublist(0, 4);
    } else {
      if (keyType != null) {
        key = _concat(key, utf8.encode(keyType));
      }
      newChecksum = RIPEMD160Digest().process(key).sublist(0, 4);
    }
    print(newChecksum);
    if (decodeBigInt(checksum) != decodeBigInt(newChecksum)) {
      throw InvalidKey("checksum error");
    }
    return key;
  }

  /// Encode key to string format using base58 encoding
  String encodeKey(Uint8List key, [String keyType]) {
    if (keyType == 'sha256x2') {
      Uint8List checksum = _sha256x2(key).sublist(0, 4);
      return base58.encode(_concat(key, checksum));
    }

    Uint8List keyBuffer = key;
    if (keyType != null) {
      keyBuffer = _concat(key, utf8.encode(keyType));
    }
    Uint8List checksum = RIPEMD160Digest().process(keyBuffer).sublist(0, 4);
    return base58.encode(_concat(keyBuffer, checksum));
  }

  /// Do SHA256 hash twice on the given data
  Uint8List _sha256x2(Uint8List data) {
    Digest d1 = sha256.convert(data);
    Digest d2 = sha256.convert(d1.bytes);
    return d2.bytes;
  }

  Uint8List _concat(Uint8List p1, Uint8List p2) {
    List<int> keyList = p1.toList();
    keyList.addAll(p2);
    return Uint8List.fromList(keyList);
  }
}

/// EOS Public Key
class EOSPublicKey extends EOSKey {
  Uint8List key;

  EOSPublicKey.fromString(String keyStr) {
    RegExp publicRegex = RegExp(r"^EOS", caseSensitive: true, multiLine: false);
    if (!publicRegex.hasMatch(keyStr)) {
      throw InvalidKey("No leading EOS");
    }
    String publicKeyStr = keyStr.substring(3);
    key = decodeKey(publicKeyStr);
  }
}

/// EOS Private Key
class EOSPrivateKey extends EOSKey {
  final String SHA256X2 = 'sha256x2';
  final int VERSION = 0x80;

  String format;
  String keyType;
  Uint8List key;

  String _checksumHashMethod;

  /// Default constructor from the key buffer itself
  EOSPrivateKey(this.key) {
    keyType = 'K1';
    _checksumHashMethod = SHA256X2;
  }

  /// Construct the private key from string
  /// It can come from WIF format for PVT format
  EOSPrivateKey.fromString(String keyStr) {
    keyType = 'K1';

    RegExp privateRegex = RegExp(r"^PVT_([A-Za-z0-9]+)_([A-Za-z0-9]+)",
        caseSensitive: true, multiLine: false);
    Iterable<Match> match = privateRegex.allMatches(keyStr);

    if (match.length == 0) {
      format = 'WIF';
      _checksumHashMethod = SHA256X2;
      // WIF
      Uint8List keyWLeadingVersion = decodeKey(keyStr, _checksumHashMethod);
      int version = keyWLeadingVersion.first;
      if (VERSION != version) {
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
      Match m = match.first;
      format = m.group(1);
      key = decodeKey(m.group(2), format);
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

    List<int> entropy = entropy1.toList();
    entropy.addAll(entropy2);
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

    List<int> keyBuffer = encodedBuffer.toList();
    keyBuffer.addAll(checksum);
    Uint8List key = Uint8List.fromList(keyBuffer);

    String publicKey = 'EOS' + base58.encode(key);

    return publicKey;
  }

  String toString() {
    List<int> version = List<int>();
    version.add(VERSION);
    Uint8List keyWLeadingVersion =
        _concat(Uint8List.fromList(version), this.key);

    return encodeKey(keyWLeadingVersion, _checksumHashMethod);
  }
}
