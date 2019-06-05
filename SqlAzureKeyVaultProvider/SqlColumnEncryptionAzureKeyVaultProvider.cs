using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;


namespace SqlAzureKeyVaultProvider
{
    internal static class Constants
    {
        /// <summary>
        /// Hashing algoirthm used for signing
        /// </summary>
        internal const string HashingAlgorithm = @"RS256";

        /// <summary>
        /// Azure Key Vault Domain Name
        /// </summary>
        internal const string AzureKeyVaultDomainName = @"vault.azure.net";

        /// <summary>
        /// Always Encrypted Param names for exec handling
        /// </summary>
        internal const string AeParamColumnEncryptionKey = "columnEncryptionKey";
        internal const string AeParamEncryptionAlgorithm = "encryptionAlgorithm";
        internal const string AeParamMasterKeyPath = "masterKeyPath";
        internal const string AeParamEncryptedCek = "encryptedColumnEncryptionKey";

    }

    public class SqlColumnEncryptionAzureKeyVaultProvider : SqlColumnEncryptionKeyStoreProvider
    {

        /// <summary>
        /// Algorithm version
        /// </summary>
        private readonly byte[] firstVersion = new byte[] { 0x01 };

        /// <summary>
        /// Constructor that takes a callback function to authenticate to AAD. This is used by KeyVaultClient at runtime 
        /// to authenticate to Azure Key Vault.
        /// </summary>
        /// <param name="authenticationCallback">Callback function used for authenticating to AAD.</param>
        public SqlColumnEncryptionAzureKeyVaultProvider(KeyVaultClient.AuthenticationCallback authenticationCallback)
        {
            if (authenticationCallback == null)
            {
                throw new ArgumentNullException("authenticationCallback");
            }

            KeyVaultClient = new KeyVaultClient(authenticationCallback);
        }

        /// <summary>
        /// Azure Key Vault Client
        /// </summary>
        public KeyVaultClient KeyVaultClient
        {
            get;
            private set;
        }

        /// <summary>
        /// This function uses the asymmetric key specified by the key path
        /// and decrypts an encrypted CEK with RSA encryption algorithm.
        /// </summary>
        /// <param name="masterKeyPath">Complete path of an asymmetric key in AKV</param>
        /// <param name="encryptionAlgorithm">Asymmetric Key Encryption Algorithm</param>
        /// <param name="encryptedColumnEncryptionKey">Encrypted Column Encryption Key</param>
        /// <returns>Plain text column encryption key</returns>
        public override byte[] DecryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] encryptedColumnEncryptionKey)
        {
            // Validate the input parameters
            ValidateNonEmptyAKVPath(masterKeyPath, isSystemOp: true);

            if (null == encryptedColumnEncryptionKey)
            {
                throw new ArgumentNullException(Constants.AeParamEncryptedCek, "Internal error. Encrypted column encryption key cannot be null.");
            }

            if (0 == encryptedColumnEncryptionKey.Length)
            {
                throw new ArgumentException(@"Internal error. Empty encrypted column encryption key specified.", Constants.AeParamEncryptedCek);
            }

            // Validate encryptionAlgorithm
            ValidateEncryptionAlgorithm(ref encryptionAlgorithm, isSystemOp: true);

            // Validate whether the key is RSA one or not and then get the key size
            int keySizeInBytes = GetAkvKeySize(masterKeyPath);

            // Validate and decrypt the EncryptedColumnEncryptionKey
            // Format is 
            //           version + keyPathLength + ciphertextLength + keyPath + ciphertext +  signature
            //
            // keyPath is present in the encrypted column encryption key for identifying the original source of the asymmetric key pair and 
            // we will not validate it against the data contained in the CMK metadata (masterKeyPath).

            // Validate the version byte
            if (encryptedColumnEncryptionKey[0] != firstVersion[0])
            {
                throw new ArgumentException(String.Format(CultureInfo.InvariantCulture, @"Specified encrypted column encryption key contains an invalid encryption algorithm version '{0}'. Expected version is '{1}'.",
                                                            encryptedColumnEncryptionKey[0].ToString(@"X2"),
                                                            firstVersion[0].ToString("X2")),
                                            Constants.AeParamEncryptedCek);
            }

            // Get key path length
            int currentIndex = firstVersion.Length;
            UInt16 keyPathLength = BitConverter.ToUInt16(encryptedColumnEncryptionKey, currentIndex);
            currentIndex += sizeof(UInt16);

            // Get ciphertext length
            UInt16 cipherTextLength = BitConverter.ToUInt16(encryptedColumnEncryptionKey, currentIndex);
            currentIndex += sizeof(UInt16);

            // Skip KeyPath
            // KeyPath exists only for troubleshooting purposes and doesnt need validation.
            currentIndex += keyPathLength;

            // validate the ciphertext length
            if (cipherTextLength != keySizeInBytes)
            {
                throw new ArgumentException(String.Format(CultureInfo.InvariantCulture, @"The specified encrypted column encryption key's ciphertext length: {0} does not match the ciphertext length: {1} when using column master key (Azure Key Vault key) in '{2}'. The encrypted column encryption key may be corrupt, or the specified Azure Key Vault key path may be incorrect.",
                                                            cipherTextLength,
                                                            keySizeInBytes,
                                                            masterKeyPath),
                                            Constants.AeParamEncryptedCek);
            }

            // Validate the signature length
            int signatureLength = encryptedColumnEncryptionKey.Length - currentIndex - cipherTextLength;
            if (signatureLength != keySizeInBytes)
            {
                throw new ArgumentException(String.Format(CultureInfo.InvariantCulture, @"The specified encrypted column encryption key's signature length: {0} does not match the signature length: {1} when using column master key (Azure Key Vault key) in '{2}'. The encrypted column encryption key may be corrupt, or the specified Azure Key Vault key path may be incorrect.",
                                                            signatureLength,
                                                            keySizeInBytes,
                                                            masterKeyPath),
                                            Constants.AeParamEncryptedCek);
            }

            // Get ciphertext
            byte[] cipherText = new byte[cipherTextLength];
            Buffer.BlockCopy(encryptedColumnEncryptionKey, currentIndex, cipherText, 0, cipherTextLength);
            currentIndex += cipherTextLength;

            // Get signature
            byte[] signature = new byte[signatureLength];
            Buffer.BlockCopy(encryptedColumnEncryptionKey, currentIndex, signature, 0, signature.Length);

            // Compute the hash to validate the signature
            byte[] hash;
            using (SHA256Cng sha256 = new SHA256Cng())
            {
                sha256.TransformFinalBlock(encryptedColumnEncryptionKey, 0, encryptedColumnEncryptionKey.Length - signature.Length);
                hash = sha256.Hash;
            }

            if (null == hash)
            {
                throw new CryptographicException("Hash should not be null while decrypting encrypted column encryption key.");
            }

            // Validate the signature
            if (!AzureKeyVaultVerifySignature(hash, signature, masterKeyPath))
            {
                throw new ArgumentException(String.Format(CultureInfo.InvariantCulture, @"The specified encrypted column encryption key signature does not match the signature computed with the column master key (Asymmetric key in Azure Key Vault) in '{0}'. The encrypted column encryption key may be corrupt, or the specified path may be incorrect.",
                                                            masterKeyPath),
                                            Constants.AeParamEncryptedCek);
            }

            // Decrypt the CEK
            return AzureKeyVaultUnWrap(masterKeyPath, encryptionAlgorithm, cipherText);
        }

        /// <summary>
        /// This function uses the asymmetric key specified by the key path
        /// and encrypts CEK with RSA encryption algorithm.
        /// </summary>
        /// <param name="masterKeyPath"></param>
        /// <param name="encryptionAlgorithm">Asymmetric Key Encryption Algorithm</param>
        /// <param name="columnEncryptionKey">Plain text column encryption key</param>
        /// <returns>Encrypted column encryption key</returns>
        public override byte[] EncryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] columnEncryptionKey)
        {
            // Validate the input parameters
            ValidateNonEmptyAKVPath(masterKeyPath, isSystemOp: false);

            if (null == columnEncryptionKey)
            {
                throw new ArgumentNullException(Constants.AeParamColumnEncryptionKey, @"Column encryption key cannot be null.");
            }

            if (0 == columnEncryptionKey.Length)
            {
                throw new ArgumentException(@"Empty column encryption key specified.", Constants.AeParamColumnEncryptionKey);
            }

            // Validate encryptionAlgorithm
            ValidateEncryptionAlgorithm(ref encryptionAlgorithm, isSystemOp: false);

            // Validate whether the key is RSA one or not and then get the key size
            int keySizeInBytes = GetAkvKeySize(masterKeyPath);

            // Construct the encryptedColumnEncryptionKey
            // Format is 
            //          version + keyPathLength + ciphertextLength + ciphertext + keyPath + signature
            //
            // We currently only support one version
            var version = new byte[] { firstVersion[0] };

            // Get the Unicode encoded bytes of cultureinvariant lower case masterKeyPath
            var masterKeyPathBytes = Encoding.Unicode.GetBytes(masterKeyPath.ToLowerInvariant());
            var keyPathLength = BitConverter.GetBytes((Int16)masterKeyPathBytes.Length);

            // Encrypt the plain text
            var cipherText = AzureKeyVaultWrap(masterKeyPath, encryptionAlgorithm, columnEncryptionKey);
            var cipherTextLength = BitConverter.GetBytes((Int16)cipherText.Length);

            if (cipherText.Length != keySizeInBytes)
            {
                throw new CryptographicException(@"cipherText length does not match the RSA key size");
            }

            // Compute hash
            // SHA-2-256(version + keyPathLength + ciphertextLength + keyPath + ciphertext) 
            byte[] hash;
            using (SHA256Cng sha256 = new SHA256Cng())
            {
                sha256.TransformBlock(version, 0, version.Length, version, 0);
                sha256.TransformBlock(keyPathLength, 0, keyPathLength.Length, keyPathLength, 0);
                sha256.TransformBlock(cipherTextLength, 0, cipherTextLength.Length, cipherTextLength, 0);
                sha256.TransformBlock(masterKeyPathBytes, 0, masterKeyPathBytes.Length, masterKeyPathBytes, 0);
                sha256.TransformFinalBlock(cipherText, 0, cipherText.Length);
                hash = sha256.Hash;
            }

            // Sign the hash
            var signedHash = AzureKeyVaultSignHashedData(hash, masterKeyPath);

            if (signedHash.Length != keySizeInBytes)
            {
                throw new CryptographicException(@"Signed hash length does not match the RSA key size");
            }

            if (!AzureKeyVaultVerifySignature(hash, signedHash, masterKeyPath))
            {
                throw new CryptographicException(@"Invalid signature of the encrypted column encryption key computed.");
            }

            // Construct the encrypted column encryption key
            // EncryptedColumnEncryptionKey = version + keyPathLength + ciphertextLength + keyPath + ciphertext +  signature
            int encryptedColumnEncryptionKeyLength = version.Length + cipherTextLength.Length + keyPathLength.Length + cipherText.Length + masterKeyPathBytes.Length + signedHash.Length;
            var encryptedColumnEncryptionKey = new byte[encryptedColumnEncryptionKeyLength];

            // Copy version byte
            int currentIndex = 0;
            Buffer.BlockCopy(version, 0, encryptedColumnEncryptionKey, currentIndex, version.Length);
            currentIndex += version.Length;

            // Copy key path length
            Buffer.BlockCopy(keyPathLength, 0, encryptedColumnEncryptionKey, currentIndex, keyPathLength.Length);
            currentIndex += keyPathLength.Length;

            // Copy ciphertext length
            Buffer.BlockCopy(cipherTextLength, 0, encryptedColumnEncryptionKey, currentIndex, cipherTextLength.Length);
            currentIndex += cipherTextLength.Length;

            // Copy key path
            Buffer.BlockCopy(masterKeyPathBytes, 0, encryptedColumnEncryptionKey, currentIndex, masterKeyPathBytes.Length);
            currentIndex += masterKeyPathBytes.Length;

            // Copy ciphertext
            Buffer.BlockCopy(cipherText, 0, encryptedColumnEncryptionKey, currentIndex, cipherText.Length);
            currentIndex += cipherText.Length;

            // copy the signature
            Buffer.BlockCopy(signedHash, 0, encryptedColumnEncryptionKey, currentIndex, signedHash.Length);

            return encryptedColumnEncryptionKey;
        }

        /// <summary>
        /// This function validates that the encryption algorithm is RSA_OAEP and if it is not,
        /// then throws an exception
        /// </summary>
        /// <param name="encryptionAlgorithm">Asymmetric key encryptio algorithm</param>
        private void ValidateEncryptionAlgorithm(ref string encryptionAlgorithm, bool isSystemOp)
        {
            // This validates that the encryption algorithm is RSA_OAEP
            if (null == encryptionAlgorithm)
            {
                if (isSystemOp)
                {
                    throw new ArgumentNullException(Constants.AeParamEncryptionAlgorithm, @"Internal error. Key encryption algorithm cannot be null.");
                }
                else
                {
                    throw new ArgumentNullException(Constants.AeParamEncryptionAlgorithm, @"Key encryption algorithm cannot be null.");
                }
            }

            // Transform to standard format (dash instead of underscore) to support both "RSA_OAEP" and "RSA-OAEP"
            if (encryptionAlgorithm.Equals("RSA_OAEP", StringComparison.OrdinalIgnoreCase))
            {
                encryptionAlgorithm = JsonWebKeyEncryptionAlgorithm.RSAOAEP;
            }

            if (string.Equals(encryptionAlgorithm, JsonWebKeyEncryptionAlgorithm.RSAOAEP, StringComparison.OrdinalIgnoreCase) != true)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, @"Invalid key encryption algorithm specified: '{0}'. Expected value: '{1}'.",
                                                            encryptionAlgorithm,
                                                            JsonWebKeyEncryptionAlgorithm.RSAOAEP),
                                            Constants.AeParamEncryptionAlgorithm);
            }
        }


        /// <summary>
        /// Checks if the Azure Key Vault key path is Empty or Null (and raises exception if they are).
        /// </summary>
        private void ValidateNonEmptyAKVPath(string masterKeyPath, bool isSystemOp)
        {
            // throw appropriate error if masterKeyPath is null or empty
            if (string.IsNullOrWhiteSpace(masterKeyPath))
            {
                string errorMessage = null == masterKeyPath
                                      ? @"Azure Key Vault key path cannot be null."
                                      : String.Format(CultureInfo.InvariantCulture, @"Invalid Azure Key Vault key path specified: '{0}'.", masterKeyPath);

                if (isSystemOp)
                {
                    throw new ArgumentNullException(Constants.AeParamMasterKeyPath, "Internal error.  " + errorMessage);
                }
                else
                {
                    throw new ArgumentException(errorMessage, Constants.AeParamMasterKeyPath);
                }

            }
            else
            {
                if (!Uri.TryCreate(masterKeyPath, UriKind.Absolute, out var parsedUri))
                {
                    // Return an error indicating that the AKV url is invalid.
                    throw new ArgumentException(String.Format(CultureInfo.InvariantCulture, @"Invalid url specified: '{0}'.", masterKeyPath), Constants.AeParamMasterKeyPath);
                }
                else
                {
                    // A valid URI.
                    // Check if it is pointing to AKV.
                    if (!parsedUri.Host.ToLowerInvariant().EndsWith(Constants.AzureKeyVaultDomainName, StringComparison.OrdinalIgnoreCase))
                    {
                        // Return an error indicating that the AKV url is invalid.
                        throw new ArgumentException(String.Format(CultureInfo.InvariantCulture, @"Invalid Azure Key Vault key path specified: '{0}'.", masterKeyPath), Constants.AeParamMasterKeyPath);
                    }

                    return;
                }
            }
        }

        /// <summary>
        /// Encrypt the text using specified Azure Key Vault key.
        /// </summary>
        /// <param name="masterKeyPath">Azure Key Vault key url.</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm.</param>
        /// <param name="columnEncryptionKey">Plain text Column Encryption Key.</param>
        /// <returns>Returns an encrypted blob or throws an exception if there are any errors.</returns>
        private byte[] AzureKeyVaultWrap(string masterKeyPath, string encryptionAlgorithm, byte[] columnEncryptionKey)
        {
            if (null == columnEncryptionKey)
            {
                throw new ArgumentNullException("columnEncryptionKey");
            }

            var wrappedKey = KeyVaultClient.WrapKeyAsync(masterKeyPath, encryptionAlgorithm, columnEncryptionKey).GetAwaiter().GetResult();
            return wrappedKey.Result;
        }

        /// <summary>
        /// Encrypt the text using specified Azure Key Vault key.
        /// </summary>
        /// <param name="masterKeyPath">Azure Key Vault key url.</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm.</param>
        /// <param name="encryptedColumnEncryptionKey">Encrypted Column Encryption Key.</param>
        /// <returns>Returns the decrypted plaintext Column Encryption Key or throws an exception if there are any errors.</returns>
        private byte[] AzureKeyVaultUnWrap(string masterKeyPath, string encryptionAlgorithm, byte[] encryptedColumnEncryptionKey)
        {
            if (null == encryptedColumnEncryptionKey)
            {
                throw new ArgumentNullException("encryptedColumnEncryptionKey");
            }

            if (0 == encryptedColumnEncryptionKey.Length)
            {
                throw new ArgumentException("encryptedColumnEncryptionKey length should not be zero");
            }


            var unwrappedKey = KeyVaultClient.UnwrapKeyAsync(masterKeyPath, encryptionAlgorithm, encryptedColumnEncryptionKey).GetAwaiter().GetResult();
            return unwrappedKey.Result;
        }

        /// <summary>
        /// Generates signature based on RSA PKCS#v1.5 scheme using a specified Azure Key Vault Key URL. 
        /// </summary>
        /// <param name="dataToSign">Text to sign.</param>
        /// <param name="masterKeyPath">Azure Key Vault key url.</param>
        /// <returns>Signature</returns>
        private byte[] AzureKeyVaultSignHashedData(byte[] dataToSign, string masterKeyPath)
        {
            Debug.Assert((dataToSign != null) && (dataToSign.Length != 0));

            var signedData = KeyVaultClient.SignAsync(masterKeyPath, Constants.HashingAlgorithm, dataToSign).GetAwaiter().GetResult();
            return signedData.Result;
        }

        /// <summary>
        /// Verifies the given RSA PKCSv1.5 signature.
        /// </summary>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <param name="masterKeyPath">Azure Key Vault key url.</param>
        /// <returns>true if signature is valid, false if it is not valid</returns>
        private bool AzureKeyVaultVerifySignature(byte[] dataToVerify, byte[] signature, string masterKeyPath)
        {
            Debug.Assert((dataToVerify != null) && (dataToVerify.Length != 0));
            Debug.Assert((signature != null) && (signature.Length != 0));

            return KeyVaultClient.VerifyAsync(masterKeyPath, Constants.HashingAlgorithm, dataToVerify, signature).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Gets the public Key size in bytes
        /// </summary>
        /// <param name="masterKeyPath">Azure Key Vault Key path</param>
        /// <returns>Key size in bytes</returns>
        private int GetAkvKeySize(string masterKeyPath)
        {
            var retrievedKey = KeyVaultClient.GetKeyAsync(masterKeyPath).GetAwaiter().GetResult();

            if (!string.Equals(retrievedKey.Key.Kty, JsonWebKeyType.Rsa, StringComparison.InvariantCultureIgnoreCase) &&
                !string.Equals(retrievedKey.Key.Kty, JsonWebKeyType.RsaHsm, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new Exception(string.Format(CultureInfo.InvariantCulture, @"Cannot use a non-RSA key: '{0}'", retrievedKey.Key.Kty));
            }

            return retrievedKey.Key.N.Length;
        }
    }
}
