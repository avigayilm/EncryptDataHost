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

        static byte[] pk = new byte[1024];

        /// <summary>
        /// Enum for the choice of action
        /// </summary>
        public enum CHOICE { ENCRYPT, DECRYPT, SIGN, GET_KEY ,GEN_KEY}

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

        #endregion

    


        /// <summary>
        /// recirves the mail from the socket
        /// </summary>
        /// <param name="sock_data"></param>
        /// <param name="session"></param>
        /// <returns></returns>
        byte[] handleClient_byte(byte[] sock_data_byte, JhiSession session)
        {
            // taking the first byte inorder to know what the command is.
            int input = (int)sock_data_byte[0];
            byte[] new_byte_array = new byte[sock_data_byte.Length - 1]; // new byte array

            // copy remaining values from original byte array to new byte array starting from index 1
            Array.Copy(sock_data_byte, 1, new_byte_array, 0, new_byte_array.Length);


            byte[] recvBuffer = new byte[400];

            switch (input)
            {
                case (int)CHOICE.ENCRYPT:
                    {
                        // in case of sending the bytes are send as UTF8
                        string sock_data = Encoding.UTF8.GetString(new_byte_array);
                        string seperator = "+/+/+/+/";

                        string[] split_data = sock_data.Split(new[] { seperator }, StringSplitOptions.None);

                        string email_addr = split_data[0];
                        string mail_body = split_data[1];

                        //get the public key
                        byte[] pk;
                        if (!PublicKeys.public_keys.ContainsKey(email_addr))
                        {
                            byte[] error = Encoding.UTF8.GetBytes("false");
                            return error;
                        }
                        else
                            pk = PublicKeys.public_keys[email_addr];


                        byte[] byte_mail_body = System.Text.Encoding.UTF8.GetBytes(mail_body);
                        //ENCRYPT                       
                        recvBuffer = EncryptData(byte_mail_body, pk, session);                  
                        return recvBuffer;
                    }
                case (int)CHOICE.DECRYPT:
                    {
                        byte[] byte_body_decrypted = new byte[2000];
                        byte_body_decrypted = DecryptData(new_byte_array, session);
                        return byte_body_decrypted;
                    }

                case (int)CHOICE.SIGN:
                    {
                        //SIGN                       
                        recvBuffer = SignData(new_byte_array, session);
                        return recvBuffer;
                    }
                case (int)CHOICE.GET_KEY:
                    {
                        string email = Encoding.UTF8.GetString(new_byte_array);
                        //Gets the public key
                        if (!PublicKeys.public_keys.ContainsKey(email))
                        {
                            // if the key is not in the dictionary than the user is not part of our platform, so an error wil be returned.
                            return Encoding.UTF8.GetBytes("false");

                        }
                        else
                            return PublicKeys.public_keys[email];
                    }
                default:
                    {
                        return Encoding.UTF8.GetBytes("false");
                    }
                    
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
            string appletPath = "C:/Users/aviga/eclipse-workspace\\EncryptData\\bin\\EncryptData.dalp";
             //string appletPath = "C:/Users/aviga/eclipse-workspace\\EncryptData\\bin\\EncryptData-debug.dalp";

            // Install the Trusted Application
            Console.WriteLine("Installing the applet.");
            jhi.Install(appletID, appletPath);

            AppletHost Instance = new AppletHost();



            // Start a session with the Trusted Application
            byte[] initBuffer = new byte[] { }; // Data to send to the applet onInit function
            Console.WriteLine("Opening a session.");
            jhi.CreateSession(appletID, JHI_SESSION_FLAGS.None, initBuffer, out session);

            //when someone would register for the addIn, the public key would be created here.
            //however becasue we need the email address we will call it from the outlook.
            byte []pk=Instance.GenerateKey(session);
            PublicKeys.public_keys.Add("avigayil.mandel@gmail.com", pk);

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
                    byte[] buffer = new byte[1024];

                    //emaildata that he receives from the client

                    //making the receivedData byte array as the length of the received bytes
                    int bytesReceived = handler.Receive(buffer);
                    byte[] receivedData = new byte[bytesReceived];
                    Buffer.BlockCopy(buffer, 0, receivedData, 0, bytesReceived);


                    //function to handle client
                    byte[] response = Instance.handleClient_byte(receivedData, session);


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