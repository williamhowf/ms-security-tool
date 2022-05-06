using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecurityApplication
{
    public class Cryptography
    {
        private string SecretKey = ConfigurationManager.AppSettings.Get("SecretKey"); //"6c7nGrky/ehjM40Ivk3p3+OeoEm9r7NCzmWexUULaa4=";  // abcd1234(SHA256)
        private string HmacKey = ConfigurationManager.AppSettings.Get("HmacKey"); //"7dEeX8uWxLLvxnUgKJipm80AiVKZKYyETsXBffxvgaY="; // 201904151653ggit2u.com(SHA256)
        private const string DECRYPT = "decrypt";
        private const string ENCRYPT = "encrypt";
        private const string SHA1 = "SHA1";
        private const string SHA256 = "SHA256";
        private const string SHA512 = "SHA512";
        private const string MD5 = "MD5";
        private string PrivateKeyCert = ConfigurationManager.AppSettings.Get("PrivateKeyCert");
        private string RsaPrivateKey = ConfigurationManager.AppSettings.Get("RsaPrivateKey"); 
        private string RsaPublicKey = ConfigurationManager.AppSettings.Get("RsaPublicKey"); 

        public Cryptography()
        {
        }

        public virtual string SHA1MessageHash(string message)
        {
            return Hashing(SHA1, message);
        }

        public virtual string SHA256MessageHash(string message)
        {
            return Hashing(SHA256, message);
        }

        public virtual string SHA512MessageHash(string message)
        {
            return Hashing(SHA512, message);
        }

        public virtual string MD5MessageHash(string message)
        {
            return Hashing(MD5, message);
        }

        public virtual string Hashing(string algorithm, string message)
        {
            string hashed = null;
            dynamic HashAlgorithm;

            switch(algorithm)
            {
                case SHA1:
                    HashAlgorithm = new SHA1Managed();
                    break;
                case SHA256:
                    HashAlgorithm = new SHA256Managed();
                    break;
                case SHA512:
                    HashAlgorithm = new SHA512Managed();
                    break;
                case MD5:
                    HashAlgorithm = new MD5CryptoServiceProvider();
                    break;
                default:
                    throw new Exception("Invalid hashing algorithm");
            }

            byte[] bufferHashed = HashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(message));
            hashed = ConvertByteToBase64String(bufferHashed);
            HashAlgorithm.Clear();
            HashAlgorithm = null;

            return hashed;
        }

        public virtual string TripleDES_Encryptor(string plainMessage, byte[] secretKey = null)
        {
            return TripleDESCrypto(plainMessage, ENCRYPT, secretKey);
        }

        public virtual string TripleDES_Decryptor(string ciphterText, byte[] secretKey = null)
        {
            return TripleDESCrypto(ciphterText, DECRYPT, secretKey);
        }

        protected virtual string TripleDESCrypto(string str,string type,byte[]secretKey)
        {
            string data = null;
            ICryptoTransform cryptoEngine = null;
            byte[] inputBuffer = null;
            byte[] results;
            byte[] defaultSecret = secretKey?.Length > 0 ? secretKey : Encoding.UTF8.GetBytes(SecretKey);
            byte[] secretkey = new byte[24]; // its because c# using 24 bytes to do encription for 3DES
            Array.Copy(defaultSecret, secretkey, 24);

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider
            {
                //set the secret key for the tripleDES algorithm
                Key = secretkey,
                //mode of operation. there are other 4 modes. We choose ECB(Electronic code Book)
                Mode = CipherMode.ECB,
                //padding mode(if any extra byte added)
                Padding = PaddingMode.PKCS7
            };

            try
            {
                switch (type)
                {
                    case DECRYPT:
                        cryptoEngine = tdes.CreateDecryptor();
                        inputBuffer = ConvertBase64StringToByte(str);
                        results = cryptoEngine.TransformFinalBlock(inputBuffer, 0, inputBuffer.Length);
                        data = Encoding.UTF8.GetString(results);
                        break;
                    case ENCRYPT:
                    default:
                        cryptoEngine = tdes.CreateEncryptor();
                        inputBuffer = Encoding.UTF8.GetBytes(str);
                        results = cryptoEngine.TransformFinalBlock(inputBuffer, 0, inputBuffer.Length);
                        data = ConvertByteToBase64String(results);
                        break;
                }

                return data;
            }
            catch
            {
                throw new Exception("Unable to encrypt/decrypt due to data input mismatch. Input => "+ str);
            }
            finally
            {
                tdes.Clear();
            }
        }

        public virtual string RSADigitalSignatureSHA1(string DataToSign)
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(DataToSign);
            RSACryptoServiceProvider RSACrypto = new RSACryptoServiceProvider(2048);

            try
            {
                //RSACrypto.FromXmlString(PrivateKeyXML);
                RSACrypto.ImportCspBlob(Convert.FromBase64String(PrivateKeyCert));
                return ConvertByteToBase64String(RSACrypto.SignData(dataToEncrypt, SHA1));
            }
            catch
            {
                return string.Empty;
            }
            finally
            {
                RSACrypto.Clear();
            }
        }

        public virtual bool VerifyRSADigitalSignatureSHA1(string OriginalData, string SignatureData)
        {
            RSACryptoServiceProvider RSAVerifier = new RSACryptoServiceProvider(2048);
            try
            {
                //RSAVerifier.FromXmlString(PrivateKeyXML);
                RSAVerifier.ImportCspBlob(Convert.FromBase64String(PrivateKeyCert));
                byte[] signedData = ConvertBase64StringToByte(SignatureData);

                return RSAVerifier.VerifyData(Encoding.UTF8.GetBytes(OriginalData), SHA1, signedData);
            }
            catch
            {
                return false;
            }
            finally
            {
                RSAVerifier.Clear();
            }
        }

        public virtual string CreateSaltKey(int size = 5)
        {
            //generate a cryptographic random number
            using (var provider = new RNGCryptoServiceProvider())
            {
                var buff = new byte[size];
                provider.GetBytes(buff);

                // Return a Base64 string representation of the random number
                return ConvertByteToBase64String(buff);
            }
        }

        public virtual string PasswordHash(string password, string saltkey, string passwordFormat = SHA512)
        {
            return CreateHash(Encoding.UTF8.GetBytes(string.Concat(password, saltkey)), passwordFormat);
        }

        public virtual string CreateHash(byte[] data, string hashAlgorithm)
        {
            if (string.IsNullOrEmpty(hashAlgorithm))
                throw new ArgumentNullException(nameof(hashAlgorithm));

            var algorithm = HashAlgorithm.Create(hashAlgorithm);
            if (algorithm == null)
                throw new ArgumentException("Unrecognized hash name");

            var hashByteArray = algorithm.ComputeHash(data);
            return BitConverter.ToString(hashByteArray).Replace("-", "");
        }

        public bool CreateBufferFile(string fileName, string secret)
        {
            bool success = false;
            try
            {
                using (FileStream stream = new FileStream(fileName, FileMode.Create)) //FileMode.Create will overwrite the file if it exist!
                {
                    using (BinaryWriter writer = new BinaryWriter(stream))
                    {
                        byte[] buf = ConvertBase64StringToByte(secret);
                        writer.Write(buf);
                        writer.Close();
                    }
                    stream.Close();
                }
                return true;
            }
            catch(Exception)
            {
                return success;
            }

        }

        public string GenerateSecretKey(string algorithm, string msg)
        {
            return Hashing(algorithm, msg);
        }
        
        public virtual byte[] HMACSignatures(string algorithm, string msg, string secret)
        {
            dynamic Hmac;
            if (string.IsNullOrWhiteSpace(secret))
                secret = HmacKey;

            byte[] key = ConvertBase64StringToByte(secret); // secret key MUST in base64 string(Hashed string)

            switch (algorithm)
            {
                case SHA1:
                    Hmac = new HMACSHA1(key);
                    break;
                case SHA256:
                    Hmac = new HMACSHA256(key);
                    break;
                case SHA512:
                    Hmac = new HMACSHA512(key);
                    break;
                default:
                    throw new Exception("Invalid hashing algorithm");
            }
            
            byte[] result = Hmac.ComputeHash(Encoding.UTF8.GetBytes(msg));
            Hmac.Clear();
            Hmac = null;

            return result;
        }

        public virtual string ConvertByteToBase64String(byte[] input)
        {
            return Convert.ToBase64String(input);
        }

        public virtual byte[] ConvertBase64StringToByte(string input)
        {
            return Convert.FromBase64String(input);
        }

        public virtual string ConvertByteToHex(byte[] input)
        {
            return BitConverter.ToString(input).Replace("-", "").ToLower();
        }

        public virtual bool HMACVerify(string algorithm, string msg, string signatures, string secret)
        {
            if (string.IsNullOrWhiteSpace(secret))
                secret = HmacKey;

            return signatures == ConvertByteToHex(HMACSignatures(algorithm, msg, secret));
        }

        public bool ValidateRsaMessageWithHash(string encryptedInput, string hashedInput)
        {
            try
            {
                return CreateHash(Encoding.UTF8.GetBytes(encryptedInput), SHA256).Equals(hashedInput);
            }
            catch
            {
                return false;
            }
        }

        public void Rsa_Encryption(string raw, out string encryptedData, out string hashedData)
        {
            encryptedData = EncryptRsaMessage(raw, RsaPublicKey);
            hashedData = CreateHash(Encoding.UTF8.GetBytes(encryptedData), SHA256);
        }

        public string Rsa_Decryption(string encryptedData)
        {
            return DecryptRsaMessage(encryptedData, RsaPrivateKey);
        }

        public virtual string EncryptRsaMessage(string rawInput, string rsaKey = "")
        {
            if (string.IsNullOrEmpty(rawInput)) return string.Empty;
            if (string.IsNullOrWhiteSpace(rsaKey)) throw new ArgumentException("Invalid Public Key");

            try
            {
                using (var rsaProvider = new RSACryptoServiceProvider())
                {
                    var inputBytes = Encoding.UTF8.GetBytes(rawInput);
                    rsaProvider.ImportCspBlob(Convert.FromBase64String(rsaKey));
                    int bufferSize = (rsaProvider.KeySize / 8) - 11;
                    var buffer = new byte[bufferSize];
                    using (MemoryStream inputStream = new MemoryStream(inputBytes), outputStream = new MemoryStream())
                    {
                        while (true)
                        {
                            int readSize = inputStream.Read(buffer, 0, bufferSize);
                            if (readSize <= 0) break;
                            var temp = new byte[readSize];
                            Array.Copy(buffer, 0, temp, 0, readSize);
                            var encryptedBytes = rsaProvider.Encrypt(temp, false);
                            outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                        }
                        return Convert.ToBase64String(outputStream.ToArray());
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        public virtual string DecryptRsaMessage(string encryptedInput, string rsaKey = "")
        {
            if (string.IsNullOrEmpty(encryptedInput)) return string.Empty;
            if (string.IsNullOrWhiteSpace(rsaKey)) throw new ArgumentException("Invalid Private Key");

            try
            {
                using (var rsaProvider = new RSACryptoServiceProvider())
                {
                    var inputBytes = Convert.FromBase64String(encryptedInput);
                    rsaProvider.ImportCspBlob(Convert.FromBase64String(rsaKey));
                    int bufferSize = rsaProvider.KeySize / 8;
                    var buffer = new byte[bufferSize];
                    using (MemoryStream inputStream = new MemoryStream(inputBytes), outputStream = new MemoryStream())
                    {
                        while (true)
                        {
                            int readSize = inputStream.Read(buffer, 0, bufferSize);
                            if (readSize <= 0) break;
                            var temp = new byte[readSize];
                            Array.Copy(buffer, 0, temp, 0, readSize);
                            var rawBytes = rsaProvider.Decrypt(temp, false);
                            outputStream.Write(rawBytes, 0, rawBytes.Length);
                        }
                        return Encoding.UTF8.GetString(outputStream.ToArray());
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        public virtual string WalletEncryptText(string toEncrypt, string SecurityKey)
        {
            byte[] keyArray;
            byte[] toEncryptArray = Encoding.UTF8.GetBytes(toEncrypt);

            //If hashing use get hashcode regards to your key
            MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
            keyArray = hashmd5.ComputeHash(Encoding.UTF8.GetBytes(SecurityKey));
            hashmd5.Clear();

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider
            {
                //set the secret key for the tripleDES algorithm
                Key = keyArray,
                //mode of operation. there are other 4 modes.
                //We choose ECB(Electronic code Book)
                Mode = CipherMode.ECB,
                //padding mode(if any extra byte added)
                Padding = PaddingMode.PKCS7
            };

            ICryptoTransform cTransform = tdes.CreateEncryptor();
            //transform the specified region of bytes array to resultArray
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            //Release resources held by TripleDes Encryptor
            tdes.Clear();
            //Return the encrypted data into unreadable string format
            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }

        public virtual string WalletDecryptText(string cipherString, string SecurityKey)
        {
            byte[] keyArray;
            byte[] toEncryptArray = Convert.FromBase64String(cipherString);

            //if hashing was used get the hash code with regards to your key
            MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
            keyArray = hashmd5.ComputeHash(Encoding.UTF8.GetBytes(SecurityKey));
            hashmd5.Clear();

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider
            {
                //set the secret key for the tripleDES algorithm
                Key = keyArray,
                //mode of operation. there are other 4 modes. 
                //We choose ECB(Electronic code Book)
                Mode = CipherMode.ECB,
                //padding mode(if any extra byte added)
                Padding = PaddingMode.PKCS7
            };

            ICryptoTransform cTransform = tdes.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            //Release resources held by TripleDes Encryptor                
            tdes.Clear();
            //return the Clear decrypted TEXT
            return Encoding.UTF8.GetString(resultArray);
        }
    }
}
