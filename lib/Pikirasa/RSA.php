<?php
namespace Pikirasa;

class RSA
{
    protected $publicKeyFile;
    protected $privateKeyFile;
    protected $password;

    public function __construct($publicKeyFile, $privateKeyFile = null, $password = null)
    {
        $this->publicKeyFile =  $this->fixKeyArgument($publicKeyFile);
        $this->privateKeyFile = $this->fixKeyArgument($privateKeyFile);
        $this->password = $password;
    }

    /**
     * Allow passing key as either file name or string.
     *
     * @param $keyFile
     *
     * @return string
     */
    public function fixKeyArgument($keyFile)
    {
        if (strncasecmp('file://', $keyFile, 7) === 0) {
            return $keyFile;
        }

        if (is_file($keyFile)) {
            return 'file://' . realpath($keyFile);
        }

        return $keyFile;
    }


    /**
     * Set password to be used during encryption and decryption
     *
     * @param string $password Certificate password
     */
    public function setPassword($password)
    {
        $this->password = $password;
    }

    /**
     * Encrypt data with provided public certificate
     *
     * @param string $data Data to encrypt
     * @return string Encrypted data
     *
     * @throws \Pikirasa\Exception
     */
    public function encrypt($data)
    {
        // Load public key
        $publicKey = openssl_pkey_get_public($this->publicKeyFile);

        if (false === $publicKey) {
            throw new Exception("OpenSSL: Unable to get public key for encryption. Is the location correct? Does this key require a password?");
        }

        $success = openssl_public_encrypt($data, $encryptedData, $publicKey);

        openssl_free_key($publicKey);

        if (!$success) {
            throw new Exception("Encryption failed. Ensure you are using a PUBLIC key.");
        }

        return $encryptedData;
    }

    /**
     * Encrypt data and then base64_encode it
     *
     * @param string $data Data to encrypt
     * @return string Base64-encrypted data
     */
    public function base64Encrypt($data)
    {
        return base64_encode($this->encrypt($data));
    }

    /**
     * Decrypt data with provided private certificate
     *
     * @param string $data Data to encrypt
     * @return string Decrypted data
     *
     * @throws \Pikirasa\Exception
     */
    public function decrypt($data)
    {
        $privateKey = $this->getPrivateKey();

        $success = openssl_private_decrypt($data, $decryptedData, $privateKey);

        openssl_free_key($privateKey);

        if ($success) {
            return $decryptedData;
        }

        throw new Exception("Decryption failed. Ensure you are using (1) A PRIVATE key, and (2) the correct one.");
    }

    /**
     * base64_decode data and then decrypt it
     *
     * @param string $data Base64-encoded data to decrypt
     * @return string Decrypted data
     */
    public function base64Decrypt($data)
    {
        return $this->decrypt(base64_decode($data));
    }

    /**
     * Determine if we have the necessary resources to do decryption.
     *
     * @return bool
     */
    public function canDecrypt()
    {
        try {
            $privateKey = $this->getPrivateKey();
            openssl_free_key($privateKey);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Return OpenSSL key resource for given private key.
     *
     * @return resource
     *
     * @throws Exception
     */
    protected function getPrivateKey()
    {
        if ($this->privateKeyFile === null) {
            throw new Exception("Unable to decrypt: No private key provided.");
        }

        $privateKey = openssl_pkey_get_private($this->privateKeyFile, $this->password);

        if (!is_resource($privateKey)) {
            throw new Exception("OpenSSL: Unable to get private key for decryption");
        }

        return $privateKey;
    }
}
