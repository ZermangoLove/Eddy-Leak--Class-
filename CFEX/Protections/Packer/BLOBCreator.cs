using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Protector.Protections.Packer
{
 class BLOB_Creator
 {
  public byte[] CreateBlob(List<byte[]> data, int key)
  {

   /*#BLOB Header -----------------------------------------------------*/

   /* ----------- EXAMPLE OF HEADER LOOK -------------------
    * HDR = Total files stored in blob ex: 3
    * Lenght of file1 ex: 256b (1)
    * lenght of file2 ex: 156b (2)
    * lenght of file3 ex: 32b  (3)
    * ...
    * ....
    * ...
    * ......
    * etc....
    * --- [END OF HEADER] ---
    */

   //Part 1: Numbers
   int blobCapacity = data.Count;
   int[] blobPartslLenghts = data.Select(n => n.Length).ToArray();
   //Part 2: file lenghts
   byte[] blobCapacityByte = BitConverter.GetBytes(blobCapacity);
   List<byte[]> blobPartslLenghtsBytes = new List<byte[]>();
   //
   //Part 3: Store part lenghts
   foreach (var partLen in blobPartslLenghts)
   {
    blobPartslLenghtsBytes.Add(BitConverter.GetBytes(partLen));
   }
   //
   List<byte[]> blobHeaderList = new List<byte[]>();
   blobHeaderList.Add(blobCapacityByte);
   foreach (var part in blobPartslLenghtsBytes)
   {
    blobHeaderList.Add(part);
   }
   int BLOB_LENGHT = sizeof(int) + (data.Count * sizeof(int));
   byte[] BLOB_HEADER = new byte[BLOB_LENGHT];

   int counter1 = 0;
   foreach (var entry in blobHeaderList)
   {
    foreach (var b in entry)
    {
     BLOB_HEADER[counter1] = b;
     counter1++;
    }
   }

   /*#BLOB Header -----------------------------------------------------*/


   List<byte[]> BLOBList = new List<byte[]>();
   BLOBList.Add(BLOB_HEADER); //Add header

   //Part 4: Store data
   int totalLenght = 0;
   foreach (byte[] pack in data)
   {
    byte[] encrypted_chunk = EncryptChunk(pack, pack.Length);
    BLOBList.Add(encrypted_chunk);
    totalLenght += pack.Length;
   }

   int blobLength = BLOB_HEADER.Length + totalLenght;
   byte[] BLOB_PLAIN = new byte[blobLength];

   int counter2 = 0;
   foreach (byte[] dpart in BLOBList)
   {
    foreach (var b in dpart)
    {
     BLOB_PLAIN[counter2] = b;
     counter2++;
    }
   }

   //Encryption
   byte[] encrypted_blob = Encrypt(BLOB_PLAIN, key);

   return encrypted_blob;
  }

  private byte[] EncryptChunk(byte[] data, int key)
  {
   List<ulong> e_0 = new List<ulong>(); //P1
   ulong[] i = SHA1.Create().ComputeHash(BitConverter.GetBytes(key)).Select(b => (ulong)(b << 8 | b << 16 | b << 24)).ToArray();
   foreach (byte b in data)
   {
    ulong n = (ulong)(b << 8 | b << 16 | b << 24); //byte to ulong
    ulong o = 0; //Initializer
    foreach (ulong iv in i)
    {
     o ^= iv; //Xor all IVS to o
    }
    o = n ^ o; //Xor o to
    e_0.Add(o);
   }
   return e_0.Select(b => (byte)(b | (b >> 8) | (b >> 16) | (b >> 24))).ToArray();
  }

  private byte[] Encrypt(byte[] input, int key)
  {
   byte[] key_ = SHA512.Create().ComputeHash(BitConverter.GetBytes(key));
   var symmetricAlgorithm = new RijndaelManaged();
   var rNGCryptoServiceProvider = new RNGCryptoServiceProvider();
   symmetricAlgorithm.Mode = CipherMode.CBC;
   symmetricAlgorithm.GenerateIV();
   byte[] array = new byte[32];
   rNGCryptoServiceProvider.GetBytes(array);
   var rfc2898DeriveBytes = new Rfc2898DeriveBytes(key_, array, 2000);
   symmetricAlgorithm.Key = rfc2898DeriveBytes.GetBytes(32);
   ICryptoTransform cryptoTransform = symmetricAlgorithm.CreateEncryptor();
   byte[] array2 = cryptoTransform.TransformFinalBlock(input, 0, input.Length);
   int dstOffset = array2.Length;
   Array.Resize<byte>(ref array2, array2.Length + array.Length);
   Buffer.BlockCopy(array, 0, array2, dstOffset, array.Length);
   dstOffset = array2.Length;
   Array.Resize<byte>(ref array2, array2.Length + symmetricAlgorithm.IV.Length);
   Buffer.BlockCopy(symmetricAlgorithm.IV, 0, array2, dstOffset, symmetricAlgorithm.IV.Length);
   return array2;
  }
 }
 class BLOBCreator
 {
 }
}
