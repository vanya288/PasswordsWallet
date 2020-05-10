using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace PasswordsWalletCryptography
{
    public class PasswordManager
    {
        private const string pepper = "SECRET_PEPPER";

        /// <summary>
        /// Gets the SHA512 hash for password
        /// </summary>
        /// <param name="_password">Password string</param>
        /// <param name="_salt">Salt string</param>
        /// <param name="_pepper">Pepper string. Optional</param>
        /// <returns>SHA512 hash in base64 string</returns>
        public string GetPasswordHashSHA512(string _password, string _salt, string _pepper = pepper)
        {
            return this.CalculateSHA512(_password + _salt + _pepper);
        }

        /// <summary>
        /// Gets the HMAC SHA512 hash for password
        /// </summary>
        /// <param name="_password">Password string</param>
        /// <param name="_salt">Salt string</param>
        /// <param name="_pepper">Pepper string. Optional</param>
        /// <returns>HMAC SHA512 hash in base64 string</returns>
        public string GetPasswordHashHMACSHA512(string _password, string _salt)
        {
            return this.CalculateHMACSHA512(_password, _salt);
        }

        /// <summary>
        /// Calculates the SHA512 hash for text
        /// </summary>
        /// <param name="_secretText">Text to be encrypted</param>
        /// <returns>SHA512 hash in base64 string</returns>
        private string CalculateSHA512(string _secretText)
        {
            string secretText = _secretText ?? "";
            var    encoding   = new ASCIIEncoding();

            byte[] secretTextBytes = encoding.GetBytes(secretText);

            using (var sha512 = SHA512.Create())
            {
                byte[] hashmessage = sha512.ComputeHash(secretTextBytes);

                return Convert.ToBase64String(hashmessage);
            }
        }

        /// <summary>
        /// Calculates the HMAC SHA512 hash for text
        /// </summary>
        /// <param name="_secretText">Text to be encrypted</param>
        /// <returns>HMAC SHA512 hash in base64 string</returns>
        private string CalculateHMACSHA512(string _password, string _salt)
        {
            string salt          = _salt ?? "";
            var    encoding      = new ASCIIEncoding();
            byte[] saltBytes     = encoding.GetBytes(salt);
            byte[] passwordBytes = encoding.GetBytes(_password);

            using (var hmacsha512 = new HMACSHA512(saltBytes))
            {
                byte[] hashmessage = hmacsha512.ComputeHash(passwordBytes);

                return Convert.ToBase64String(hashmessage);
            }
        }

        /// <summary>
        /// Encrypts the password with AES algorytm
        /// </summary>
        /// <param name="_password">Password string</param>
        /// <param name="_primaryPasswordHash">Key string</param>
        /// <returns>Encrypted password in base64 string</returns>
        public string EncryptPasswordAES(string _password, string _primaryPasswordHash)
        {
            byte[] md5Key = this.CalculateMD5(_primaryPasswordHash);

            return this.EncryptAES(_password, md5Key);
        }

        /// <summary>
        /// Decrypts the password 
        /// </summary>
        /// <param name="_passwordHash">Password hash to be decrypted</param>
        /// <param name="_primaryPasswordHash">Key string</param>
        /// <returns>Decrypted password string</returns>
        public string DecryptPasswordAES(string _passwordHash, string _primaryPasswordHash)
        {
            byte[] md5Key = this.CalculateMD5(_primaryPasswordHash);

            return this.DecryptAES(_passwordHash, md5Key);
        }

        /// <summary>
        /// Performs the AES encryption
        /// </summary>
        /// <param name="_password">Password string</param>
        /// <param name="_key">Key string</param>
        /// <returns>Encrypted password in base64 string</returns>
        private string EncryptAES(string _password, byte[] _key)
        {
            // Check arguments.
            if (_password == null || _password.Length <= 0)
            {
                throw new ArgumentNullException("_password");
            }

            if (_key == null || _key.Length <= 0)
            {
                throw new ArgumentNullException("_key");
            }

            byte[] encrypted;
            byte[] iv = new byte[16];

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key     = _key;
                aesAlg.IV      = iv;
                aesAlg.Padding = PaddingMode.Zeros;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(_password);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Performs the AES decryption 
        /// </summary>
        /// <param name="_encryptedPassword">Encrypted password string</param>
        /// <param name="_key">Key string</param>
        /// <returns>Decrypted password</returns>
        private string DecryptAES(string _encryptedPassword, byte[] _key)
        {
            // Check arguments.
            if (_encryptedPassword == null || _encryptedPassword.Length <= 0)
            {
                throw new ArgumentNullException("_encryptedPassword");
            }

            if (_key == null || _key.Length <= 0)
            {
                throw new ArgumentNullException("_key");
            }

            // Declare the string used to hold
            // the decrypted text.
            string plaintext      = null;
            byte[] iv             = new byte[16];
            byte[] encryptedBytes = Convert.FromBase64String(_encryptedPassword);

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key     = _key;
                aesAlg.IV      = iv;
                aesAlg.Padding = PaddingMode.Zeros;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(encryptedBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        /// <summary>
        /// Calculates the MD5 for text
        /// </summary>
        /// <param name="_secretText">Text value</param>
        /// <returns>The computed hash for text</returns>
        private byte[] CalculateMD5(string _secretText)
        {
            string secretText = _secretText ?? "";
            var    encoding   = new ASCIIEncoding();

            byte[] secretTextBytes = encoding.GetBytes(secretText);
            byte[] hashmessage;

            using (var md5 = MD5.Create())
            {
                hashmessage = md5.ComputeHash(secretTextBytes);
            }

            return hashmessage;
        }

        /// <summary>
        /// Generates the salt string
        /// </summary>
        /// <param name="_saltLength">Salt length</param>
        /// <returns>The generated salt in base64 string</returns>
        public string GenerateSaltString(int _saltLength)
        {
            return Convert.ToBase64String(this.GenerateSaltBytes(_saltLength));
        }

        /// <summary>
        /// Generates the salt bytes
        /// </summary>
        /// <param name="_saltLength">Salt length</param>
        /// <returns>The generated salt bytes</returns>
        private byte[] GenerateSaltBytes(int _saltLength = 64)
        {
            RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            byte[]                   randomBytes              = new byte[_saltLength];

            rngCryptoServiceProvider.GetBytes(randomBytes);

            return randomBytes;
        }
    }

}
