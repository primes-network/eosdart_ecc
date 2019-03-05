class InvalidKey implements Exception {
  String cause;

  InvalidKey(this.cause);

  String toString() => cause;
}
