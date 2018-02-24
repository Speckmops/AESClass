/*
                           __                           __     
                         /'__`\                  __    /\ \    
 _____      __     _ __ /\ \/\ \    ___     ___ /\_\   \_\ \   
/\ '__`\  /'__`\  /\`'__\ \ \ \ \ /' _ `\  / __`\/\ \  /'_` \  
\ \ \L\ \/\ \L\.\_\ \ \/ \ \ \_\ \/\ \/\ \/\ \L\ \ \ \/\ \L\ \ 
 \ \ ,__/\ \__/.\_\\ \_\  \ \____/\ \_\ \_\ \____/\ \_\ \___,_\
  \ \ \/  \/__/\/_/ \/_/   \/___/  \/_/\/_/\/___/  \/_/\/__,_ /
   \ \_\                                                       
    \/_/                                      addicted to code


Copyright (C) 2018  Stefan 'par0noid' Zehnpfennig

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.IO.Compression;

namespace par0noid
{
    public static class AESClass
    {
        public static int PBKDF2_MinIterations = 10000;
        public static int PBKDF2_MaxIterations = 20000;
        public static int PBKDF2_SaltSize = 64;
        public static Encoding DefaultEncoding = Encoding.Default;
        public static CipherMode CipherMode = CipherMode.CBC;

        public static byte[] Decrypt_Byte2Byte(byte[] data, byte[] Password, bool Compression = false) => Decrypt(data, Password, Compression);
        public static byte[] Encrypt_Byte2Byte(byte[] data, byte[] Password, bool Compression = false) => Encrypt(data, Password, Compression);
        public static string Decrypt_Byte2String(byte[] data, byte[] Password, bool Compression = false) => GetString(Decrypt(data, Password, Compression));
        public static string Encrypt_Byte2String(byte[] data, byte[] Password, bool Compression = false) => GetString(Encrypt(data, Password, Compression));
        public static byte[] Decrypt_String2Byte(string data, byte[] Password, bool Compression = false) => Decrypt(GetBytes(data), Password, Compression);
        public static byte[] Encrypt_String2Byte(string data, byte[] Password, bool Compression = false) => Encrypt(GetBytes(data), Password, Compression);
        public static string Decrypt_String2String(string data, byte[] Password, bool Compression = false) => GetString(Decrypt(GetBytes(data), Password, Compression));
        public static string Encrypt_String2String(string data, byte[] Password, bool Compression = false) => GetString(Encrypt(GetBytes(data), Password, Compression));
        public static byte[] Decrypt_Byte2Byte(byte[] data, string Password, bool Compression = false) => Decrypt(data, Password, Compression);
        public static byte[] Encrypt_Byte2Byte(byte[] data, string Password, bool Compression = false) => Encrypt(data, Password, Compression);
        public static string Decrypt_Byte2String(byte[] data, string Password, bool Compression = false) => GetString(Decrypt(data, Password, Compression));
        public static string Encrypt_Byte2String(byte[] data, string Password, bool Compression = false) => GetString(Encrypt(data, Password, Compression));
        public static byte[] Decrypt_String2Byte(string data, string Password, bool Compression = false) => Decrypt(GetBytes(data), Password, Compression);
        public static byte[] Encrypt_String2Byte(string data, string Password, bool Compression = false) => Encrypt(GetBytes(data), Password, Compression);
        public static string Decrypt_String2String(string data, string Password, bool Compression = false) => GetString(Decrypt(GetBytes(data), Password, Compression));
        public static string Encrypt_String2String(string data, string Password, bool Compression = false) => GetString(Encrypt(GetBytes(data), Password, Compression));
        public static string Decrypt_Base64String2String(string data, byte[] Password, bool Compression = false) => GetString(Decrypt(Convert.FromBase64String(data), Password, Compression));
        public static string Encrypt_Base64String2String(string data, byte[] Password, bool Compression = false) => GetString(Encrypt(Convert.FromBase64String(data), Password, Compression));
        public static string Decrypt_String2Base64String(string data, byte[] Password, bool Compression = false) => Convert.ToBase64String(Decrypt(GetBytes(data), Password, Compression));
        public static string Encrypt_String2Base64String(string data, byte[] Password, bool Compression = false) => Convert.ToBase64String(Encrypt(GetBytes(data), Password, Compression));
        public static byte[] Decrypt_Base64String2Byte(string data, byte[] Password, bool Compression = false) => Decrypt(Convert.FromBase64String(data), Password, Compression);
        public static byte[] Encrypt_Base64String2Byte(string data, byte[] Password, bool Compression = false) => Encrypt(Convert.FromBase64String(data), Password, Compression);
        public static string Decrypt_Byte2Base64String(byte[] data, byte[] Password, bool Compression = false) => Convert.ToBase64String(Decrypt(data, Password, Compression));
        public static string Encrypt_Byte2Base64String(byte[] data, byte[] Password, bool Compression = false) => Convert.ToBase64String(Encrypt(data, Password, Compression));
        public static string Decrypt_Base64String2Base64String(string data, byte[] Password, bool Compression = false) => Convert.ToBase64String(Decrypt(Convert.FromBase64String(data), Password, Compression));
        public static string Encrypt_Base64StringBase64String(string data, byte[] Password, bool Compression = false) => Convert.ToBase64String(Encrypt(Convert.FromBase64String(data), Password, Compression));
        public static string Decrypt_Base64String2String(string data, string Password, bool Compression = false) => GetString(Decrypt(Convert.FromBase64String(data), Password, Compression));
        public static string Encrypt_Base64String2String(string data, string Password, bool Compression = false) => GetString(Encrypt(Convert.FromBase64String(data), Password, Compression));
        public static string Decrypt_String2Base64String(string data, string Password, bool Compression = false) => Convert.ToBase64String(Decrypt(GetBytes(data), Password, Compression));
        public static string Encrypt_String2Base64String(string data, string Password, bool Compression = false) => Convert.ToBase64String(Encrypt(GetBytes(data), Password, Compression));
        public static byte[] Decrypt_Base64String2Byte(string data, string Password, bool Compression = false) => Decrypt(Convert.FromBase64String(data), Password, Compression);
        public static byte[] Encrypt_Base64String2Byte(string data, string Password, bool Compression = false) => Encrypt(Convert.FromBase64String(data), Password, Compression);
        public static string Decrypt_Byte2Base64String(byte[] data, string Password, bool Compression = false) => Convert.ToBase64String(Decrypt(data, Password, Compression));
        public static string Encrypt_Byte2Base64String(byte[] data, string Password, bool Compression = false) => Convert.ToBase64String(Encrypt(data, Password, Compression));
        public static string Decrypt_Base64String2Base64String(string data, string Password, bool Compression = false) => Convert.ToBase64String(Decrypt(Convert.FromBase64String(data), Password, Compression));
        public static string Encrypt_Base64StringBase64String(string data, string Password, bool Compression = false) => Convert.ToBase64String(Encrypt(Convert.FromBase64String(data), Password, Compression));

        private static byte[] Decrypt(byte[] data, string Password, bool Compression = false) => Decrypt(data, Encoding.Default.GetBytes(Password), Compression);

        private static byte[] Decrypt(byte[] data, byte[] Password, bool Compression = false)
        {
            try
            {
                int Iterations = BitConverter.ToInt32(data, 0);

                byte[] IV = new byte[16];
                byte[] Salt = new byte[PBKDF2_SaltSize];
                byte[] EncryptedData = new byte[data.Length - PBKDF2_SaltSize - 16 - 4];

                Array.Copy(data, 4, IV, 0, 16);
                Array.Copy(data, 4 + 16, Salt, 0, PBKDF2_SaltSize);
                Array.Copy(data, 4 + 16 + PBKDF2_SaltSize, EncryptedData, 0, EncryptedData.Length);

                byte[] Result = null;

                using (AesManaged AES = new AesManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Mode = CipherMode;
                    Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(Password, Salt, Iterations);
                    AES.Key = rfc2898.GetBytes(AES.KeySize / 8);
                    AES.IV = IV;

                    ICryptoTransform aes_decryptor = AES.CreateDecryptor(AES.Key, AES.IV);

                    using (MemoryStream ms = new MemoryStream(EncryptedData))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, aes_decryptor, CryptoStreamMode.Read))
                        {
                            byte[] buffer = new byte[1024];

                            int readed = 0;

                            do
                            {
                                readed = cs.Read(buffer, 0, buffer.Length);

                                if (readed > 0)
                                {
                                    if (Result == null)
                                    {
                                        Result = new byte[readed];
                                        Array.Copy(buffer, 0, Result, 0, readed);
                                    }
                                    else
                                    {
                                        int offset = Result.Length;
                                        Array.Resize(ref Result, Result.Length + readed);
                                        Array.Copy(buffer, 0, Result, offset, readed);
                                    }
                                }

                            } while (readed > 0);
                        }

                        if(Compression)
                        {
                            return Decompress(Result);
                        }
                        else
                        {
                            return Result;
                        }
                    }
                }
            }
            catch { throw new Exception("Decryption failed"); }
        }

        private static byte[] Encrypt(byte[] data, string Password, bool Compression = false) => Encrypt(data, Encoding.Default.GetBytes(Password), Compression);

        private static byte[] Encrypt(byte[] data, byte[] Password, bool Compression = false)
        {
            try
            {
                if(Compression)
                {
                    data = Compress(data);
                }

                List<byte> result = new List<byte>();

                using (AesManaged AES = new AesManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    if (PBKDF2_MinIterations < 1 || PBKDF2_MinIterations > PBKDF2_MaxIterations)
                    {
                        throw new Exception("PBKDF2_MinIterations illegal value");
                    }

                    int Iterations = new Random().Next(PBKDF2_MinIterations, PBKDF2_MaxIterations);

                    Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(Encoding.Default.GetString(Password), PBKDF2_SaltSize, Iterations);

                    AES.Key = rfc2898.GetBytes(AES.KeySize / 8);
                    AES.IV = new byte[16];
                    AES.GenerateIV();
                    AES.Mode = CipherMode;

                    result.AddRange(BitConverter.GetBytes(Iterations));
                    result.AddRange(AES.IV);
                    result.AddRange(rfc2898.Salt);

                    ICryptoTransform aes_encryptor = AES.CreateEncryptor(AES.Key, AES.IV);

                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, aes_encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(data, 0, data.Length);
                        }
                        result.AddRange(ms.ToArray());
                    }
                }

                return result.ToArray();

            }
            catch { throw new Exception("Encryption failed"); }
        }

        private static byte[] Compress(byte[] data)
        {
            try
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Compress))
                    {
                        ds.Write(data, 0, data.Length);
                    }
                    return ms.ToArray();
                }
            }
            catch
            {
                throw new Exception("Compression failed");
            }
        }

        private static byte[] Decompress(byte[] data)
        {
            try
            {
                using (MemoryStream decompressedMS = new MemoryStream())
                {
                    using (MemoryStream compressMS = new MemoryStream(data))
                    {
                        using (DeflateStream ds = new DeflateStream(compressMS, CompressionMode.Decompress))
                        {
                            ds.CopyTo(decompressedMS);
                        }
                    }
                    return decompressedMS.ToArray();
                }
            }
            catch
            {
                throw new Exception("Decompression failed");
            }
        }

        private static string GetString(byte[] data) => DefaultEncoding.GetString(data);
        private static byte[] GetBytes(string data) => DefaultEncoding.GetBytes(data);
        
    }
}
