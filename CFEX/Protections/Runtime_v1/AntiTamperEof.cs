﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Reflection;
using System.Diagnostics;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;
using Microsoft.VisualBasic;

namespace Eddy_Protector_Runtime
{
 class AntiTamperEof
 {
  public static void Initialize()
  {

   #region NotUsed
   //if((int)Math.Sqrt((double)(Mutation.KeyI0 % (~(Mutation.KeyI1 - (Mutation.KeyI2 * (Mutation.KeyI3 - (Mutation.KeyI4 + (Mutation.KeyI5 + (((Mutation.KeyI6 * (Mutation.KeyI7 % Mutation.KeyI8))))))))) + (Mutation.KeyI9) ^ (Mutation.KeyI10) * (Mutation.KeyI11 / Mutation.KeyI12 - Mutation.KeyI13)))) == Mutation.KeyI14)
   //{
   // Environment.FailFast("Acess denied 0x22228");
   //}
   #endregion

   /* Get MD5 Hash from end of file */
   byte[] Result = null;

   String normalizedFileName = Path.GetFullPath(Environment.ExpandEnvironmentVariables(Process.GetCurrentProcess().MainModule.FileName));
   byte[] originalFile = File.ReadAllBytes(normalizedFileName);

   Byte[] buffer = new Byte[4];
   FileInfo information = new FileInfo(normalizedFileName);
   if (information.Exists)
   {
    using (Stream stream = information.Open(FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
    {
     stream.Seek(0x3c, SeekOrigin.Begin);
     stream.Read(buffer, 0, 4);
     Int32 e_lfanew = BitConverter.ToInt32(buffer, 0);
     stream.Seek(e_lfanew + 0x6, SeekOrigin.Begin);
     stream.Read(buffer, 0, 2);
     Int16 dwNumSections = BitConverter.ToInt16(buffer, 0);
     stream.Seek(e_lfanew + 0x54, SeekOrigin.Begin);
     stream.Read(buffer, 0, 4);
     Int32 dwSizeHeaders = BitConverter.ToInt32(buffer, 0);
     Int64 dwSize = dwSizeHeaders;
     for (Int32 i = 0; i < dwNumSections; i++)
     {
      stream.Seek((e_lfanew + 0xf8 + (i * 40)) + 0x10, SeekOrigin.Begin);
      stream.Read(buffer, 0, buffer.Length);
      dwSize += BitConverter.ToInt32(buffer, 0);
     }

     FileInfo information_ = new FileInfo(normalizedFileName);
     if (information.Exists)
     {
      Int64 dwSize_ = information.Length;
      Int64 dwRealSize = dwSize;
      Int64 dwExtra = dwSize_ - dwRealSize;
      if (dwExtra > 0)
      {
       Byte[] buffer_ = new Byte[dwExtra];
       using (Stream stream_ = information.Open(FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
       {
        stream.Seek(dwRealSize, SeekOrigin.Begin);
        stream.Read(buffer_, 0, buffer_.Length);
        Result = buffer_;
       }
      }
     }
    }
   }
   /* -------------------------------------------------------------------------------------------------------------- */

   /* Substract 128 bytes from entrire file */
   byte[] RealData = new byte[originalFile.Length - 129];
   for (int f = 0; f < RealData.Length; f++)
   {
    RealData[f] = originalFile[f];
   }
   /* -------------------------------------------------------------- */

   /* Decrypt RealData 129bytes */
   string k = "49330C65-18D8-420B-97F0-41242CD5494F";
   byte[] Key = SHA512.Create().ComputeHash(Encoding.ASCII.GetBytes(String.Format("{2}{3}{6}{1}{5}{0}{4}", (char)((((32 + 65) + (('N') - (33 + 34))) < ((char)0x5C) ? (k[17]) : (k[5]))), (char)((((char)0x5E) > ((39 + 40) + (k[11])) ? ('M') : ((char)(40 + 40))) + (((']') < (0x48 + (0x4B + ((0x75 + (((char)0x51) - (28 + 57))) - 0x57))) ? ('T') : ((108 + ((93 + ((105 + (('M') - 0x46)) - 87)) - 0x5A)) - (42 + 42))) - (((('U') - 0x4D) > (0x54 + ((0x69 + ((103 + (((char)(43 + 44)) - 0x46)) - 0x47)) - 0x5B)) ? ((80 + (((char)92) - 0x4B)) - 0x58) : ((0x53 + ((0x49 + (((29 + 59) + ((0x50 + (((26 + 52) + (((char)0x5D) - (37 + 38))) - 0x43)) - 86)) - 78)) - 0x46)) - 0x4C))))), (char)((((char)78) < (((34 + 35) + ((0x72 + (('L') - 0x47)) - 67)) - (38 + 38)) ? (115 + (('H') - 91)) : ((char)0x45))), (char)(((('W') - 0x4A) < (73 + ('W')) ? (0x48 + ((107 + (('R') - 0x58)) - 73)) : ((0x53 + (('S') - 67)) - 0x57))), (char)((((char)80) < ((0x5F + (((22 + 45) + ((0x6A + ((66 + ((108 + ((0x4D + (((28 + 58) + ((101 + (((40 + 41) + (('\\') - 0x44)) - 0x5C)) - (28 + 58))) - (29 + 60))) - 0x5C)) - 0x51)) - (27 + 54))) - 0x53)) - 0x58)) - 0x46) ? ((0x71 + (((22 + 45) + ((0x48 + ((0x63 + ((100 + (((28 + 57) + ((0x44 + (((58 + 58) + ((0x56 + ((0x59 + (((26 + 53) + (('V') - 66)) - (27 + 56))) - 79)) - 0x5B)) - 0x57)) - 0x5B)) - 0x57)) - (27 + 54))) - 0x56)) - (25 + 52))) - 0x4E)) - 91) : ('G')) - ((((94 + ((0x4C + ((101 + ((0x4A + ((101 + (('T') - 0x46)) - 0x50)) - (29 + 59))) - 0x59)) - 0x5C)) - 0x58) > (0x71 + ((char)0x50)) ? ((char)0x4E) : ((k[11]) - 87)))), (char)((((char)0x4D) < ((24 + 48) + ((80 + ((0x6A + (((char)0x41) - 0x42)) - 0x58)) - 68)) ? ('G') : ('V')) + (((0x5B + ('T')) < ('\\') ? ((0x6F + (('^') - 0x4F)) - 79) : (k[11])) - ((((char)95) < (0x4F + ('^')) ? ((char)(42 + 43)) : ('W')) - (((((char)0x53) - 81) < ((0x4A + ((0x65 + ((0x43 + ((100 + (((32 + 65) + ((']') - 78)) - 74)) - 0x5B)) - 0x5B)) - (37 + 37))) - 0x45) ? ((73 + (((22 + 46) + ('Q')) - 91)) - 0x5B) : ((0x48 + ('H')) - 91)))))), (char)(((67 + (((56 + 57) + (((char)0x5D) - 88)) - 87)) < ((27 + 56) + ((35 + 71) + (('S') - 0x5B))) ? ((char)85) : ((75 + ((0x6A + ((91 + ((104 + (((char)0x5A) - 0x53)) - (30 + 61))) - 76)) - 0x5A)) - 0x44)) + (((((55 + 55) + ((86 + (((33 + 66) + (('Q') - (22 + 44))) - 0x59)) - 85)) - (37 + 37)) > ((70 + ((0x5B + (((32 + 64) + (((char)74) - 71)) - 88)) - 76)) - 0x4D) ? ((0x5A + (((char)0x57) - 0x50)) - (27 + 55)) : ((112 + ((k[5]) - 0x48)) - 72)))))));
   for (int i = 0; i <= Result.Length; i++)
   {
    Result[i % Result.Length] = Convert.ToByte((Convert.ToInt32(Result[i % Result.Length] ^ Key[i % Key.Length]) - Convert.ToInt32(Result[(i + 1) % Result.Length]) + 256) % 256);
   }
   Array.Resize(ref Result, Result.Length - 1);
   /* ---------------------------------------------------------------- */

   /* Compute hash from resulted bytes eg. Entire assembly [] */
   string hash = string.Empty;
   byte[] hashComputed = SHA512.Create().ComputeHash(RealData);

   for (int c = 0; c < hashComputed.Length; c++)
   {
    hash += hashComputed[c].ToString("X2");
   }
   /* ---------------------------------------------------------------- */

   /* Ge ASCIII numbers from hash */
   int num0 = 0;
   char[] char0 = Encoding.ASCII.GetString(Result).ToCharArray();
   for (int i = 0; i < char0.Length; i++)
   {
    num0 += (int)char0[i] ^ (i + 1) >> 24;
   }

   int num1 = 0;
   char[] char1 = hash.ToCharArray();
   for (int i = 0; i < char1.Length; i++)
   {
    num1 += (int)char1[i] ^ (i + 1) >> 24;
   }
   /* --------------------------------------------------------------------- */

   /* Control flow expression */
   //if ((int)Math.Sqrt((double)(Mutation.KeyI0 % (~(Mutation.KeyI1 - (Mutation.KeyI2 * (Mutation.KeyI3 - (Mutation.KeyI4 + (Mutation.KeyI5 + (((Mutation.KeyI6 * (Mutation.KeyI7 % Mutation.KeyI8))))))))) + (Mutation.KeyI9) ^ (Mutation.KeyI10) * (Mutation.KeyI11 / Mutation.KeyI12 - Mutation.KeyI13)))) == Mutation.KeyI14)
   //{
   if (num0 != num1)
   {
    Process.GetCurrentProcess().Kill();
   }
   else
   {
    var reg_ = Registry.CurrentUser;
    string m = "3BD43AD4-0200-4054-8E59-AAAC271E6C13";
    string key_hive = String.Format("{4}{1}{18}{13}{14}{9}{15}{3}{10}{12}{20}{7}{2}{0}{8}{19}{17}{5}{6}{11}{16}", (char)((((char)(35 + 36)) > ((38 + 77) + (((char)0x5D) - (22 + 46))) ? ((0x4C + (((39 + 78) + (('Y') - 0x51)) - 0x51)) - 0x51) : ('V')) - (((m[2]) > (0x53 + (77 + (((35 + 70) + (((0x51 + ((0x55 + (((42 + 43) + (((36 + 73) + (((char)95) - 67)) - 81)) - 80)) - (28 + 58))) - (25 + 52)) - (35 + 35))) - 80))) ? (((58 + 59) + (('K') - 85)) - (37 + 37)) : ((((35 + 71) + ((0x5C + (((34 + 35) + ((0x6B + (((51 + 51) + (((86 + (((23 + 47) + (((47 + 48) + ((85 + ((0x5F + ((0x43 + ((100 + ((0x5B + (((char)0x5C) - 78)) - 0x4E)) - (45 + 45))) - 0x4D)) - 0x49)) - 0x51)) - 0x58)) - 0x4F)) - 75) - 0x44)) - (24 + 48))) - 0x56)) - 0x55)) - (46 + 46))) - 0x47) - 0x48)))), (char)(((0x48 + ((0x42 + (((33 + 68) + (('X') - 0x44)) - 0x50)) - 76)) < (80 + ((0x68 + (('S') - (28 + 57))) - 85)) ? ((0x65 + (((char)80) - 0x45)) - 0x4C) : ('J')) + ((('N') > ((58 + 58) + (((char)0x4F) - 92)) ? ((0x45 + ((0x49 + ((0x75 + ((0x46 + ((0x4E + ((76 + (((50 + 50) + (('G') - 0x45)) - 0x43)) - 0x55)) - 0x45)) - 0x4E)) - 87)) - 0x4F)) - 74) : ((char)(42 + 42))) + ((((0x75 + ((((33 + 66) + ((114 + (((0x4C + ((0x46 + (((41 + 41) + ((char)71)) - 0x5B)) - (22 + 46))) - 0x57) - 0x45)) - 66)) - 0x4D) - 69)) - 0x42) < (0x6D + ((106 + ((79 + (((36 + 73) + (('O') - 84)) - (27 + 56))) - 89)) - 85)) ? ('X') : ((101 + (('Z') - 72)) - 0x42)) + ((('Y') < ((40 + 40) + ((46 + 47) + (((char)0x56) - 71))) ? ((char)73) : ((0x59 + ((107 + (((24 + 49) + ((0x52 + ((0x64 + ((81 + ((66 + ((67 + ((0x60 + (((31 + 63) + ((0x63 + (('Y') - 76)) - 89)) - (43 + 43))) - 66)) - (29 + 58))) - 88)) - 73)) - (29 + 59))) - 0x5A)) - 0x4A)) - 0x5C)) - 84)) + (((('H') - 67) > ((39 + 40) + ((35 + 70) + (((char)(29 + 58)) - 74))) ? ((0x70 + ((0x66 + (((char)0x5A) - (23 + 48))) - 0x51)) - 0x59) : ((char)(42 + 42))) + ((((0x67 + (((char)(44 + 44)) - 69)) - (29 + 58)) < ((char)0x58) ? (((((('^') - (42 + 43)) - 0x5C) - 84) - (44 + 45)) - (34 + 34)) : (0x70 + (('L') - 91))))))))), (char)((((67 + ((0x54 + ((0x54 + ((92 + ((0x47 + ((0x53 + ((67 + ((93 + ((0x44 + ((69 + ((89 + (((47 + 47) + ((0x59 + (((35 + 71) + (((99 + (((49 + 50) + ((0x72 + (((char)(29 + 60)) - (30 + 61))) - 72)) - (45 + 46))) - 0x58) - 66)) - (25 + 51))) - 0x47)) - (29 + 58))) - (26 + 52))) - 0x4C)) - 0x48)) - (42 + 42))) - 0x4E)) - (33 + 34))) - 92)) - 88)) - 82)) - (30 + 60))) - 70) > (0x56 + (((char)0x5C) - 69)) ? ((100 + ((0x4E + ((0x45 + ((107 + ((0x59 + ((0x75 + (((char)(27 + 54)) - 0x4F)) - (46 + 46))) - 84)) - 0x4F)) - 0x54)) - 0x53)) - 0x56) : ('X')) + (((76 + (106 + ((m[2]) - 0x4C))) < ((0x6F + ((0x5E + (('Q') - 66)) - (37 + 37))) - 0x52) ? ((102 + (((35 + 36) + (((31 + 64) + ((113 + ((97 + (((char)0x4D) - 0x4B)) - 0x57)) - 85)) - 85)) - (44 + 45))) - 0x4B) : ((char)0x4B)) - (((0x58 + ('[')) > (76 + (((char)90) - 0x44)) ? (((51 + 52) + (((char)81) - 74)) - 68) : (((33 + 34) + ((0x6E + (((char)0x51) - 0x58)) - 0x46)) - 0x55))))), (char)((((32 + 64) + ((char)0x56)) < ((0x5A + (((31 + 62) + (('V') - 0x52)) - (40 + 40))) - 71) ? (((52 + 53) + (((char)(37 + 37)) - (34 + 34))) - 84) : ((char)86)) - ((((22 + 46) + (0x54 + ((0x5D + ((85 + (('V') - (36 + 36))) - 85)) - 0x5A))) > (((36 + 36) + (m[1])) - 0x56) ? ((0x5B + (((char)0x5E) - 81)) - 87) : (m[5])))), (char)(((((33 + 66) + (('\\') - (44 + 44))) - 0x49) < (((33 + 34) + ((char)76)) - 0x57) ? ('S') : ((0x6F + (((char)80) - 87)) - 91))), (char)(((0x43 + ((0x75 + (((51 + 51) + (('S') - 76)) - 88)) - 0x50)) > (((char)(25 + 50)) - 0x45) ? ((0x53 + ((0x57 + (((49 + 49) + ((99 + ((0x52 + ((0x5A + ((100 + (('T') - 80)) - 86)) - 0x59)) - 89)) - 76)) - 92)) - 0x58)) - 75) : ((0x4C + ((0x74 + (((char)0x4D) - 0x51)) - 0x46)) - 0x51))), (char)((('X') > (89 + (('Z') - 0x50)) ? ((82 + ((0x75 + ((82 + ((0x47 + ((112 + (('Z') - (38 + 38))) - 83)) - 0x59)) - 81)) - (43 + 44))) - (25 + 52)) : ((char)0x47)) - (((100 + ((char)0x5F)) < (((25 + 50) + ((0x51 + (((36 + 74) + ((0x56 + (((55 + 55) + (('G') - 70)) - 84)) - 91)) - (45 + 46))) - (25 + 52))) - 0x4D) ? ((0x4F + ((111 + (('L') - (22 + 44))) - 0x5C)) - (44 + 44)) : ('I')) - (((0x4B + ((102 + ((0x42 + ((92 + ((0x6F + (((char)(42 + 43)) - 0x5B)) - 74)) - (42 + 42))) - 76)) - 77)) < ((0x63 + ((0x4F + ((91 + ((72 + ((0x51 + (((char)0x5B) - 67)) - 0x47)) - 89)) - 0x54)) - 0x57)) - 84) ? ((46 + 46) + (('T') - 0x4D)) : ('T')) + (((((char)79) - (33 + 33)) > ((0x57 + ((0x51 + ((0x44 + ((0x53 + ((98 + (((42 + 42) + ((0x6F + ((80 + ((0x42 + (((46 + 46) + ((102 + (((char)90) - 0x59)) - 0x46)) - (27 + 56))) - 0x4A)) - 90)) - 0x5A)) - 0x4E)) - 0x55)) - 0x59)) - 68)) - 77)) - 0x57) ? ((0x54 + (((char)0x5D) - 73)) - 0x5C) : ('P')) + (((0x49 + (m[20])) > ((0x45 + (((31 + 63) + ((102 + (('\\') - 0x59)) - 0x45)) - 68)) - (45 + 45)) ? ('X') : (m[5])) - ((((22 + 44) + (0x5F + ((0x72 + ((((48 + 48) + ((0x4F + ((88 + ((0x48 + ((86 + ((95 + (((39 + 78) + ((m[20]) - (25 + 52))) - (38 + 39))) - (25 + 51))) - 91)) - (27 + 56))) - 0x48)) - (43 + 44))) - 85) - 0x46)) - 0x43))) < ('_') ? (('Y') - 0x59) : ('G')) + ((((0x71 + (('L') - 66)) - 0x44) < ((char)0x48) ? (70 + ((0x4D + ((77 + ((0x4D + ((0x4C + ((85 + ((0x55 + (((34 + 35) + (((32 + 66) + (((38 + 39) + ((0x70 + ((0x5C + (('\\') - 0x57)) - (36 + 36))) - 0x4B)) - 0x56)) - (45 + 45))) - (26 + 52))) - 0x56)) - 0x4B)) - 0x4B)) - (29 + 59))) - (35 + 36))) - 74)) : (((char)(43 + 44)) - (25 + 52)))))))))), (char)(((0x61 + (((36 + 73) + ((0x44 + (((41 + 41) + (((29 + 58) + ((108 + (((char)0x4A) - 0x4D)) - 0x51)) - 0x5A)) - 0x49)) - 79)) - (30 + 61))) < (((39 + 78) + (('L') - 69)) - 92) ? ((43 + 44) + (((33 + 67) + (((char)0x53) - 0x52)) - 89)) : ((char)0x56)) + ((((0x6C + ((m[27]) - 0x48)) - 0x43) < (((48 + 49) + ((0x71 + (((0x5E + (((29 + 60) + ((0x4D + ((0x44 + ((84 + ((0x6D + ((0x66 + ((0x66 + (((char)84) - 0x4B)) - (30 + 61))) - (27 + 55))) - 0x58)) - 0x59)) - 0x4B)) - 0x4B)) - (28 + 56))) - 0x5A) - 0x4D)) - 0x4D)) - 0x42) ? ('L') : ('R')) + (((0x60 + ((117 + (((char)0x46) - (29 + 59))) - 79)) > ((0x4E + ((0x5F + (((char)0x5A) - 0x53)) - 71)) - 78) ? ('V') : ((char)(24 + 49))) - (((((38 + 78) + (('J') - 0x58)) - (23 + 47)) < (0x51 + ((char)89)) ? (0x6E + ((105 + ((0x62 + (((char)91) - 0x56)) - 0x56)) - 84)) : ((0x6E + ((m[20]) - 73)) - 0x57)))))), (char)(((0x4C + ((0x49 + ((72 + ((74 + ((0x52 + ((0x59 + ((0x70 + ((0x75 + ((m[2]) - 0x52)) - 0x4C)) - 0x51)) - (43 + 44))) - 0x54)) - 0x5A)) - 90)) - 0x43)) > (('N') - (23 + 47)) ? (m[27]) : (0x42 + ((0x57 + ((0x49 + ((0x6D + (('\\') - 0x58)) - (37 + 38))) - (38 + 38))) - (45 + 45))))), (char)((((43 + 43) + ('I')) < ('V') ? ((29 + 58) + ((']') - 0x52)) : ((char)0x51)) - (((0x42 + ((38 + 39) + ((0x6F + ((m[1]) - (23 + 46))) - 81))) < (((22 + 46) + (((33 + 66) + ((0x6D + (('F') - 0x4A)) - (25 + 51))) - 0x50)) - (42 + 42)) ? ((0x49 + ((0x4E + ((94 + ((88 + (((52 + 52) + (((char)0x58) - (38 + 38))) - (26 + 54))) - 75)) - 0x59)) - 0x4A)) - 86) : ((0x65 + ((m[2]) - 0x42)) - (43 + 44))))), (char)((('\\') < ((47 + 47) + ((char)0x48)) ? ('W') : (((36 + 73) + (((80 + ((0x6A + (((24 + 48) + ((0x56 + (((char)0x5C) - (33 + 34))) - 68)) - 0x57)) - (26 + 52))) - (24 + 49)) - (22 + 45))) - (26 + 52))) - ((('W') < (']') ? ('M') : ('X')) - ((((char)0x53) > ((36 + 36) + ((0x60 + ((0x4B + ((0x66 + ((0x72 + (((char)(38 + 38)) - (22 + 44))) - (39 + 39))) - 0x54)) - 84)) - 0x58)) ? ((char)0x5C) : ((char)0x54)) + ((((char)0x5A) < ((84 + ((0x6D + (((char)0x5D) - 81)) - 0x57)) - (23 + 48)) ? ((0x6B + (('H') - (22 + 46))) - 0x4C) : (m[27])) - ((('O') < ((0x6B + (((49 + 50) + ((0x55 + (((29 + 58) + ((78 + ((0x4A + ((0x60 + (((char)0x47) - 0x47)) - 74)) - 0x46)) - 0x5A)) - (36 + 37))) - (44 + 45))) - 0x5B)) - 81) ? (m[2]) : ((char)(38 + 39))) - ((((0x5F + ((0x66 + (('O') - 0x4B)) - 0x46)) - 67) < (m[5]) ? ((char)0x50) : (((char)0x5C) - 84)) + ((((37 + 37) + (0x59 + ((95 + (((char)0x55) - 0x48)) - (25 + 51)))) < ((0x6C + ((106 + (((char)88) - 0x4D)) - 0x51)) - (42 + 43)) ? (((50 + 51) + ((0x57 + (('\\') - 77)) - 0x48)) - 82) : ('R')) - (((((46 + 47) + ((79 + ((68 + ((89 + (((49 + 49) + (('L') - 0x4E)) - 0x43)) - (43 + 43))) - (22 + 44))) - 0x49)) - (25 + 52)) < (((char)0x52) - (33 + 33)) ? ((0x69 + (('_') - (41 + 42))) - 70) : (0x57 + (m[27]))))))))))), (char)((((0x61 + ((0x50 + ((0x5E + (((36 + 74) + (((char)0x52) - 0x5A)) - 0x45)) - 85)) - 0x55)) - 79) > ((0x4A + (m[5])) - 87) ? ((0x5C + ((103 + (((36 + 73) + (('G') - 0x48)) - 0x52)) - 73)) - 91) : (((char)93) - 0x46))), (char)(((0x6C + (((char)0x5C) - 0x4F)) < ('_') ? (((char)(26 + 54)) - 0x4B) : (m[20]))), (char)((((95 + ((0x62 + (('T') - 75)) - 78)) - (34 + 35)) < (111 + ((71 + ((76 + ('G')) - 88)) - 0x50)) ? ((char)0x54) : ((0x69 + (((char)(39 + 39)) - 0x56)) - (46 + 46)))), (char)((((0x5B + (('U') - 0x46)) - 0x59) < ((char)0x54) ? ('I') : (0x69 + (((char)78) - (43 + 43)))) + (((0x43 + (66 + ((75 + (((55 + 55) + ((109 + (((char)0x50) - 0x45)) - 89)) - 0x57)) - 0x4D))) > ((0x5B + ((0x63 + (((char)0x5E) - (35 + 36))) - (30 + 61))) - 68) ? ((char)77) : ((0x49 + (m[1])) - (44 + 45))) - (((m[1]) > ((42 + 43) + ((char)0x50)) ? (('^') - (30 + 60)) : ('P')) - ((((0x4D + ((0x5B + (((30 + 61) + ((0x59 + ((0x69 + (((char)0x52) - 0x43)) - 0x4E)) - 85)) - 79)) - 0x57)) - 85) > ('K') ? ((0x4C + (((char)(47 + 48)) - 0x44)) - 0x42) : ((0x44 + (((50 + 50) + (((22 + 46) + ((88 + ((66 + ((0x74 + (('W') - (43 + 43))) - 68)) - (36 + 37))) - (30 + 60))) - 0x53)) - 91)) - 0x55)))))), (char)(((('U') - 0x42) < (83 + ((char)0x56)) ? ((char)0x4C) : (('Z') - 83)) + ((((0x71 + ((0x74 + (((98 + ((0x71 + (((char)0x4D) - (37 + 38))) - (24 + 50))) - (41 + 42)) - (36 + 36))) - 0x5B)) - (30 + 61)) < ((0x6C + (('J') - 0x49)) - (46 + 46)) ? ((0x74 + (((108 + (((36 + 73) + (('R') - 0x5B)) - (22 + 44))) - 0x55) - 0x4C)) - 0x55) : (((char)83) - 77)))), (char)(((0x58 + (('X') - 0x4D)) > (0x68 + ((0x74 + (((103 + ((116 + (((24 + 48) + ((76 + ((113 + (('H') - 79)) - 0x56)) - 0x44)) - 0x5A)) - 0x4B)) - (30 + 62)) - (27 + 54))) - (33 + 34))) ? (((char)0x59) - 0x50) : ((char)(30 + 62)))), (char)((('H') < ((100 + ((0x61 + (((char)0x5A) - 68)) - (41 + 42))) - (43 + 43)) ? ('L') : ((0x4D + ((0x61 + (((54 + 54) + (('H') - 82)) - 72)) - 0x44)) - (41 + 41)))), (char)(((94 + ((0x48 + ((0x52 + ((0x55 + (((25 + 52) + (m[20])) - 0x56)) - 0x59)) - 0x51)) - 69)) > ((92 + (((33 + 67) + (((25 + 51) + ((0x64 + (((char)90) - 84)) - (36 + 37))) - 83)) - 70)) - 0x55) ? ((char)70) : ('_'))), (char)((((72 + (((39 + 78) + ((87 + ((0x6A + (((char)(44 + 45)) - 0x54)) - 0x5A)) - 90)) - 0x4B)) - (35 + 36)) < (0x55 + ((char)(46 + 47))) ? ((char)0x46) : ((107 + (('S') - 0x49)) - 0x45)) + (((89 + ((0x5E + (('\\') - 0x4D)) - 88)) < ('W') ? ((char)0x4E) : ((91 + (('O') - 0x4A)) - (25 + 51))))), (char)(((']') < (108 + ((char)0x56)) ? ((char)87) : ((75 + ((0x4F + ((110 + ((76 + ((0x43 + ((0x48 + (((33 + 68) + (('Z') - 0x4D)) - 0x4C)) - 0x42)) - 0x4D)) - 0x59)) - 0x59)) - 74)) - (23 + 48))) + (((0x59 + ((0x69 + (('O') - (38 + 38))) - 82)) < ((0x5C + ((0x4D + (((char)(30 + 60)) - 67)) - 0x4D)) - (23 + 47)) ? (((char)0x5C) - (24 + 49)) : (m[20])) - ((((0x47 + (((38 + 78) + (('_') - 0x5C)) - 0x4A)) - 0x4C) > (0x73 + ((char)(39 + 40))) ? (0x59 + (((char)0x53) - 73)) : ((0x4E + ((107 + (((char)(46 + 46)) - 0x46)) - 0x47)) - (26 + 54))))))) + Conversion.Hex(Mutation.KeyI15); //EOFKEY is 15
    reg_.CreateSubKey(key_hive);
    var reg__ = Registry.CurrentUser.OpenSubKey(key_hive, true);
    reg__.SetValue(Conversion.Hex(Mutation.KeyI15), (Mutation.KeyI0 % (~(Mutation.KeyI1 - (Mutation.KeyI2 * (Mutation.KeyI3 - (Mutation.KeyI4 + (Mutation.KeyI5 + (((Mutation.KeyI6 * (Mutation.KeyI7 % Mutation.KeyI8))))))))) + (Mutation.KeyI9) ^ (Mutation.KeyI10) * (Mutation.KeyI11 / Mutation.KeyI12 - Mutation.KeyI13))));
   }
  }
  //}

 }
}
