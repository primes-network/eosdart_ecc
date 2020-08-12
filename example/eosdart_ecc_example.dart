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
  EOSSignature signature = privateKey.signString(data);
  // Print the EOS signature
  print(signature.toString());

  // Recover the EOSPublicKey used to dign the data
  var recoveredPublicKey = signature.recover(data);
  print(recoveredPublicKey.toString());

  // Verify the data using the signature
  signature.verify(data, publicKey);
}
