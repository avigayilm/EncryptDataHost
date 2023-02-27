using Intel.Dal;
using System;
using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;

namespace EncryptDataHost
{
    /// <summary>
    /// dictionary to save the public keys of all the users.
    /// </summary>
    static class PublicKeys
    {
        public static Dictionary<string, byte[]> public_keys = new Dictionary<string, byte[]>();
    }
    class AppletHost
    {
        /// <summary>
        /// Enum for the choice of action
        /// </summary>
        public enum CHOICE { SIGN_ENCRYPT, VERIFY_DECRYPT, SIGN, VERIFY }

        /// <summary>
        /// enum for the applet
        /// </summary>
        public enum CMD
        {
            GENERATE_KEY,
            SIGN_DATA,
            ENCRYPT_DATA,
            DECRYPT_DATA,
        };

        /// <summary>
        /// public key consisiting of mod and exp
        /// </summary>
        public struct KeyComponents
        {
            byte[] modulus;
            byte[] exponent;

            public byte[] Modulus { get => modulus; set => modulus = value; }
            public byte[] Exponent { get => exponent; set => exponent = value; }
        }

        #region functions

        /// <summary>
        /// Signs the data and returns the signature
        /// </summary>
        /// <param name="dataToSign"></param>
        /// <param name="session"></param>
        /// <returns>signature</returns>
        public byte[] SignData(byte[] dataToSign, JhiSession session)
        {
            int responseCode;
            byte[] signature = new byte[2000];
            Jhi.Instance.SendAndRecv2(session, (int)CMD.SIGN_DATA, dataToSign, ref signature, out responseCode);
            return signature;
        }

        /// <summary>
        /// generates the key and returns the public key(mod[256],exp[4])
        /// </summary>
        /// <param name="session"></param>
        /// <returns></returns>
        public byte[] GenerateKey(JhiSession session)
        {
            int responseCode;
            byte[] sendBuffer = new byte[] { 0 };
            byte[] public_key = new byte[2000];
            Jhi.Instance.SendAndRecv2(session, (int)CMD.GENERATE_KEY, sendBuffer, ref public_key, out responseCode);
            return public_key;
        }

        /// <summary>
        /// Encypts the data with the public key of the receiver and returns the encrypted data.
        /// </summary>
        /// <param name="dataToEncrypt"></param>
        /// <param name="key"></param>
        /// <param name="session"></param>
        /// <returns></returns>
        public byte[] EncryptData(byte[] dataToEncrypt, byte[] publicKey, JhiSession session)
        {
            int responseCode;
            byte[] recvBuffer = new byte[2000];
            byte[] sendBuffer = new byte[publicKey.Length + dataToEncrypt.Length];
            Buffer.BlockCopy(publicKey, 0, sendBuffer, 0, publicKey.Length);
            Buffer.BlockCopy(dataToEncrypt, 0, sendBuffer, publicKey.Length, dataToEncrypt.Length);
            Jhi.Instance.SendAndRecv2(session, (int)CMD.ENCRYPT_DATA, sendBuffer, ref recvBuffer, out responseCode);
            return recvBuffer;
        }

        /// <summary>
        /// decrypt the data with his private key( applet) and returns the decrypted data.
        /// </summary>
        /// <param name="dataToDecrypt"></param>
        /// <param name="session"></param>
        /// <returns></returns>
        public byte[] DecryptData(byte[] dataToDecrypt, JhiSession session)
        {
            int responseCode;
            byte[] decrypted = new byte[2000];
            Jhi.Instance.SendAndRecv2(session, (int)CMD.DECRYPT_DATA, dataToDecrypt, ref decrypted, out responseCode);
            return decrypted;
        }

        /// <summary>
        /// Seperates the public key into mod and exp.
        /// </summary>
        /// <param name="pk"></param>
        /// <returns>mod, exp</returns>
        public Tuple<byte[], byte[]> GetModExp(byte[] pk)
        {
            byte[] modulus = new byte[256];
            Buffer.BlockCopy(pk, 0, modulus, 0, 256);
            byte[] exponent = new byte[4];
            Buffer.BlockCopy(pk, 256, exponent, 0, 4);
            return Tuple.Create(modulus, exponent);
        }
        /// <summary>
        /// converts the hexadecimal string to a byte array
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public byte[] StringHexToByte(string hex)
        {
            string[] hexValues = hex.Split('-');
            byte[] byteArray = new byte[hexValues.Length];
            for (int i = 0; i < hexValues.Length; i++)
            {
                byteArray[i] = Convert.ToByte(hexValues[i], 16);
            }
            return byteArray;
        }

        public bool Verify(byte[] data, byte[] signature, byte[] pk)
        {
            var mod_exp = GetModExp(pk);
            Org.BouncyCastle.Math.BigInteger mod = new Org.BouncyCastle.Math.BigInteger(1, mod_exp.Item1);
            Org.BouncyCastle.Math.BigInteger exp = new Org.BouncyCastle.Math.BigInteger(1, mod_exp.Item2);
            RsaKeyParameters param = new RsaKeyParameters(false, mod, exp);
            ISigner signClientSide = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
            signClientSide.Init(false, param);
            signClientSide.BlockUpdate(data, 0, data.Length);
            return signClientSide.VerifySignature(signature);
        }
        #endregion

        /// <summary>
        /// recirves the mail from the socket
        /// </summary>
        /// <param name="sock_data"></param>
        /// <param name="session"></param>
        /// <returns></returns>
        byte[] handleClient(string sock_data, JhiSession session)
        {

            string seperator = "#*#*#*#*";
            byte[] byte_seperator = System.Text.Encoding.UTF8.GetBytes(seperator);
            string[] split_data = sock_data.Split(new[] { seperator }, StringSplitOptions.None);
            Int32.TryParse(split_data[0], out int input);
            //Int32.TryParse(sock_data[0], out int input);
            string email_addr = split_data[1];
            string mail_body = split_data[2];

            //Gets the public key
            byte[] pk;
            if (!PublicKeys.public_keys.ContainsKey(email_addr))
            {
                pk = GenerateKey(session);
                PublicKeys.public_keys.Add(email_addr, pk);
            }
            else
                pk = PublicKeys.public_keys[email_addr];

            switch (input)
            {
                case (int)CHOICE.SIGN_ENCRYPT:
                    {
                        byte[] byte_mail_body = System.Text.Encoding.UTF8.GetBytes(mail_body);
                        //SIGN
                        byte[] signature = SignData(byte_mail_body, session);
                        //ENCRYPT                       
                        byte[] recvBuffer = EncryptData(byte_mail_body, pk, session);
                        byte[] rslt = recvBuffer.Concat(byte_seperator.Concat(signature)).ToArray();
                        return rslt;
                    }
                case (int)CHOICE.VERIFY_DECRYPT:
                    {

                        //string[] context = mail_body.Split(new[] { BitConverter.ToString(byte_seperator) }, StringSplitOptions.None);
                        //string body = context[0];
                        //string signature = context[1];
                        string body = email_addr;
                        string signature = mail_body;
                        //DECRYPT
                       // byte[] byte_body_encrypted = StringHexToByte(body);
                        byte[] byte_body_encrypted = System.Text.Encoding.UTF8.GetBytes(body); 
                        byte[] byte_body_decrypted = new byte[2000];
                        byte_body_decrypted = DecryptData(byte_body_encrypted, session);
                        // string rslt = System.Text.Encoding.UTF8.GetString(byte_body_decrypted);
                        //VERIFY
                        // to verify we need the original text data which is: byte_body_decrypted
                        // and we need the signatuer which is the byte_signature
                        // verifiy the data
                        //byte[] byte_signature = StringHexToByte(body);
                        byte[] byte_signature=System.Text.Encoding.UTF8.GetBytes(signature);
                        bool is_verify = Verify(byte_body_decrypted, byte_signature, pk);
                        if (is_verify)
                            return byte_body_decrypted;
                        else
                            return Encoding.UTF8.GetBytes("false");
                    }

                case (int)CHOICE.SIGN:
                    {
                        byte[] byte_mail_body = System.Text.Encoding.UTF8.GetBytes(mail_body);
                        byte[] signature = SignData(byte_mail_body, session);
                        byte[] sep_sign = byte_seperator.Concat(signature).ToArray();
                        byte[] enter= Encoding.UTF8.GetBytes("\n\n");
                        return byte_mail_body.Concat(enter.Concat(sep_sign).ToArray()).ToArray();
                    }
                case (int)CHOICE.VERIFY:
                    {

                        //string[] context = mail_body.Split(new[] { BitConverter.ToString(byte_seperator) }, StringSplitOptions.None);
                        //string body = context[0];
                        //string signature = context[1];
                        string body = email_addr;
                        string signature = mail_body;
                        byte[] byte_mail_body = System.Text.Encoding.UTF8.GetBytes(body);
                        //byte[]byte_signature = System.Text.Encoding.UTF8.GetBytes(signature);
                        byte[] byte_signature = StringHexToByte(signature);
                        bool is_verify = Verify(byte_mail_body, byte_signature, pk);
                        if (is_verify)
                            return Encoding.UTF8.GetBytes("true");
                        else
                            return Encoding.UTF8.GetBytes("false");
                    }
                default:
                    {
                        return Encoding.UTF8.GetBytes("error");
                    }


                    //case (int)CMD.SIGN_DATA:
                    //    {
                    //        byte[] temp2 = Instance.GenerateKey(session);
                    //        userKey.Modulus = new byte[256];
                    //        Buffer.BlockCopy(pk, 0, userKey.Modulus, 0, 256);
                    //        userKey.Exponent = new byte[4];
                    //        Buffer.BlockCopy(pk, 256, userKey.Exponent, 0, 4);
                    //        Console.WriteLine("Enter the message to encode");
                    //        string str = Console.ReadLine();
                    //        byte[] byteArray = System.Text.Encoding.UTF8.GetBytes(str);
                    //        // the recvBuffer has the signature
                    //        recvBuffer = Instance.SignData(byteArray, session);


                    //        Console.WriteLine("This is the message with the signature \n");
                    //        Console.WriteLine(BitConverter.ToString(recvBuffer));

                    //        // to verify we need the original text data which is: bytearray
                    //        // and we need the signatuer which is recvBuffer
                    //        // verifiy the daya
                    //        Org.BouncyCastle.Math.BigInteger mod = new Org.BouncyCastle.Math.BigInteger(1, userKey.Modulus);
                    //        Org.BouncyCastle.Math.BigInteger exp = new Org.BouncyCastle.Math.BigInteger(1, userKey.Exponent);
                    //        RsaKeyParameters param = new RsaKeyParameters(false, mod, exp);
                    //        byte[] tmpSource = byteArray;
                    //        ISigner signClientSide = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
                    //        signClientSide.Init(false, param);
                    //        signClientSide.BlockUpdate(tmpSource, 0, tmpSource.Length);
                    //        bool unsigned = signClientSide.VerifySignature(recvBuffer);
                    //        Console.WriteLine(unsigned);

                    //        break;
                    //    }
                    //case (int)CMD.VALIDATE_SIGN:
                    //    {
                    //        Console.WriteLine("Enter the message to encode");
                    //        string str = Console.ReadLine();
                    //        byte[] byteArray = System.Text.Encoding.UTF8.GetBytes(str);
                    //        byte[] temp = new byte[2000];
                    //        temp = Instance.SignData(byteArray, session);
                    //        Console.WriteLine("This is the message with the signature \n");
                    //        Console.WriteLine(BitConverter.ToString(temp));




                    //        break;
                    //    }
                    //case (int)CMD.ENCRYPT_DATA:
                    //    {
                    //        byte[] temp = new byte[2000];
                    //        Console.WriteLine("Enter the message to encode");
                    //        string str = Console.ReadLine();
                    //        byte[] byteArray = System.Text.Encoding.UTF8.GetBytes(str);
                    //        temp = Instance.GenerateKey(session);
                    //        recvBuffer = Instance.EncryptData(byteArray, temp, session);
                    //        break;
                    //    }
                    //case (int)CMD.DECRYPT_DATA:
                    //    {

                    //        byte[] temp = new byte[2000];
                    //        Console.WriteLine("Enter the message to encode\n");
                    //        string str = Console.ReadLine();
                    //        byte[] byteArray = System.Text.Encoding.UTF8.GetBytes(str);
                    //        Console.WriteLine(BitConverter.ToString(byteArray));
                    //        Console.WriteLine("This up was the string in byte \n");
                    //        temp = Instance.GenerateKey(session);
                    //        recvBuffer = Instance.EncryptData(byteArray, temp, session);
                    //        Console.WriteLine("Encoded message\n");
                    //        Console.WriteLine(BitConverter.ToString(recvBuffer));



                    //        Console.WriteLine("Enter the message to dencode\n");
                    //        //string str = Console.ReadLine();
                    //        //byte[] byteArray = System.Text.Encoding.UTF8.GetBytes(str);
                    //        byte[] result = new byte[2000];
                    //        result = Instance.DecryptData(recvBuffer, session);
                    //        Console.WriteLine(BitConverter.ToString(result));
                    //        Console.WriteLine("This was the bytes decoded\n");
                    //        string outt = System.Text.Encoding.UTF8.GetString(result);
                    //        Console.WriteLine(outt);
                    //        Console.Write("This was the string decoded\n");
                    //        break;
                    //    }

            }
        }
        static void Main(string[] args)
        {

            #region initialize the applet
#if AMULET
            // When compiled for Amulet the Jhi.DisableDllValidation flag is set to true 
            // in order to load the JHI.dll without DLL verification.
            // This is done because the JHI.dll is not in the regular JHI installation folder, 
            // and therefore will not be found by the JhiSharp.dll.
            // After disabling the .dll validation, the JHI.dll will be loaded using the Windows search path
            // and not by the JhiSharp.dll (see http://msdn.microsoft.com/en-us/library/7d83bc18(v=vs.100).aspx for 
            // details on the search path that is used by Windows to locate a DLL) 
            // In this case the JHI.dll will be loaded from the $(OutDir) folder (bin\Amulet by default),
            // which is the directory where the executable module for the current process is located.
            // The JHI.dll was placed in the bin\Amulet folder during project build.
            Jhi.DisableDllValidation = true;
#endif
            Jhi jhi = Jhi.Instance;
            JhiSession session;


            // This is the UUID of this Trusted Application (TA).
            //The UUID is the same value as the applet.id field in the Intel(R) DAL Trusted Application manifest.
            string appletID = "5200ffd2-b2e2-402e-bacc-97013469e012";
            // This is the path to the Intel Intel(R) DAL Trusted Application .dalp file that was created by the Intel(R) DAL Eclipse plug-in.
            //string appletPath = "C:/Users/aviga/eclipse-workspace\\EncryptData\\bin\\EncryptData.dalp";
             string appletPath = "C:/Users/aviga/eclipse-workspace\\EncryptData\\bin\\EncryptData-debug.dalp";

            // Install the Trusted Application
            Console.WriteLine("Installing the applet.");
            jhi.Install(appletID, appletPath);

            AppletHost Instance = new AppletHost();



            // Start a session with the Trusted Application
            byte[] initBuffer = new byte[] { }; // Data to send to the applet onInit function
            Console.WriteLine("Opening a session.");
            jhi.CreateSession(appletID, JHI_SESSION_FLAGS.None, initBuffer, out session);

            #endregion



            #region connect to the socket

            // Create a TCP/IP socket object.
            Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            // Bind the socket to the local endpoint and listen for incoming connections.
            try
            {
                listener.Bind(new IPEndPoint(IPAddress.Any, 8080));
                //max 10 connections
                listener.Listen(10);

                while (true)
                {
                    Console.WriteLine("Waiting for a connection...");

                    // Accept incoming connection requests.
                    Socket handler = listener.Accept();
                    Console.WriteLine("Client connected");

                    // Receive the data from the client and send a response.
                    byte[] buffer = new byte[4096];

                    //emaildata that he receives from the client
                    int bytesReceived = handler.Receive(buffer);
                    string data = Encoding.ASCII.GetString(buffer, 0, bytesReceived);

                    //string data = Convert.ToBase64String(buffer);

                    //function to handle client
                    byte[] response = Instance.handleClient(data, session);
                    Console.WriteLine(Encoding.ASCII.GetString(response));
                    //Console.WriteLine("Received message: {0}", data);
                    //byte[] response = Encoding.ASCII.GetBytes("Hello from the server!");
                    handler.Send(response);

                    // Close the socket.
                    handler.Shutdown(SocketShutdown.Both);
                    handler.Close();
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

            #endregion


            // Close the session
            Console.WriteLine("Closing the session.");
            jhi.CloseSession(session);

            //Uninstall the Trusted Application
            Console.WriteLine("Uninstalling the applet.");
            jhi.Uninstall(appletID);

            Console.WriteLine("Press Enter to finish.");
            Console.Read();
        }
    }
}