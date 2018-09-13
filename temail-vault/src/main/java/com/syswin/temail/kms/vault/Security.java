package com.syswin.temail.kms.vault;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public interface Security {

  KeyPair getKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException;

  byte[] encrypt(SecretKey shareKey, String plaintext)
      throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException;

  String decrypt(SecretKey shareKey, byte[] encryptedBytes) throws Exception;

  byte[] sign(PrivateKey privateKey, byte[] unsigned) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;

  boolean verify(byte[] publicKey, byte[] unsigned, byte[] signed);
}
