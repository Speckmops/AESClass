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
using System.Text;

namespace par0noid
{
    class Program
    {
        static void Main(string[] args)
        {
            //The password. It is also possible to use byte[] as password
            string Password = "secret";

            //Inputs
            string InString = "This is a test";
            byte[] InByte = Encoding.Default.GetBytes(InString);
            string InBase64 = Convert.ToBase64String(InByte);

            //Outputs
            string OutString = AESClass.Encrypt_String2String(InString, Password);
            byte[] OutByte = AESClass.Encrypt_String2Byte(InString, Password);
            string OutBase64 = AESClass.Encrypt_String2Base64String(InString, Password);

            //More testing..
            byte[] encrypted = AESClass.Encrypt_Byte2Byte(new byte[] { 0,1,2,3,4,5,6,7,8,9 }, Password);
            string encryptedB64 = AESClass.Encrypt_Byte2Base64String(new byte[] { 0,1,2,3,4,5,6,7,8,9 }, Password);
            byte[] decrypted = AESClass.Decrypt_Byte2Byte(encrypted, Password);
            string decryptedFromB64 = AESClass.Decrypt_Base64String2String(encryptedB64, Password);

            //You can convert everything from byte[], string, base64string to byte[], string, base64string
        }
    }
}
