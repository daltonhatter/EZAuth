using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.IO;
using System.Net;

namespace EZAuth
{
    public class Manager
    {
        private Encryption encryption = new Encryption();
        // Seed for all random string generators
        private string seed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";
        private string keyPath = @"C:\temp\EZAuth.key";

        #region Public Methods


        /// <summary>
        /// Generates a unique Serial Number / Product ID
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        // Probably won't use this in C#. Will more than likely be handled in PHP
        public string GenerateSN(uint length)
        {
            string SerialNumber = "";
            Random rnd = new Random();
            for (int i = 0; i < length; i++)
            {
                int range = rnd.Next(0, seed.Length); // Random number within the range of index's of 'seed'
                SerialNumber += seed[range];
            }

            return SerialNumber;
        }


        /// <summary>
        /// Simply creates an EZAuth.key file and with encrypted key - Best practice is to use in correlation to isFirstLaunch()
        /// </summary>
        /// <param name="rawSN"></param>
        public void SetLocalSN(string rawSN)
        {
            File.WriteAllText(keyPath, encryption.Encrypt(rawSN));
        }


        /// <summary>
        /// Matches local Serial Number log to Database. If one doesn't exist, returns false. If Serial's match, will return true.
        /// </summary>
        public bool MatchLocalSN(string dbSN)
        {
            if(dbSN == null || String.IsNullOrEmpty(dbSN))
            {
                throw new ArgumentNullException("dbSN", "Failed to pass a valid parameter to dbSN. Make sure you are passing a non-null, non-empty string");
            }
            if (!File.Exists(keyPath)) return false;
            string localSN = GetLocalSN();

            return dbSN == localSN;
        }


        /// <summary>
        /// Returns a List of type 'string' containing the system's Processor, Motherboard, and GPU
        /// </summary>
        /// <returns></returns>
        public List<string> GetSystemInfo()
        {
            List<string> systemInfo = new List<string>();

            string processor = GetComponent("Win32_Processor", "Name");
            string Mobo = GetComponent("Win32_BaseBoard", "Product");
            string GPU = GetComponent("Win32_VideoController", "Name");

            systemInfo.Add(processor);
            systemInfo.Add(Mobo);
            systemInfo.Add(GPU);

            return systemInfo;
        }


        /// <summary>
        /// Checks file system for EZAuth key file. Returns true if the file does not exist
        /// </summary>
        /// <returns></returns>
        public bool isFirstLaunch()
        {
            if(File.Exists(keyPath))
            {
                return (File.ReadAllText(keyPath) == "");
            }

            return true;
        }


        /// <summary>
        /// Uses checkip.dyndns.org to fetch the user's ip and returns it as a string
        /// </summary>
        /// <returns></returns>
        public string GetUserIP()
        {
            string Address = "";
            WebRequest request = WebRequest.Create("http://checkip.dyndns.org/");
            using (WebResponse response = request.GetResponse())
            {
                using (StreamReader stream = new StreamReader(response.GetResponseStream()))
                {
                    Address = stream.ReadToEnd();
                }
                // stream reader should return: <html><head><title>Current IP Check</title></head><body>Current IP Address: 1.1.1.1</body></html>
                int first = Address.IndexOf("Address: ") + 9;
                int last = Address.IndexOf("</body>");
                Address = Address.Substring(first, last - first);
                return Address;
            }
        }

        #endregion
        #region Private Methods


        private string GetLocalSN()
        {
            string decryptedKey = "";
            string encryptedKey = File.ReadAllText(keyPath);
            try
            {
                decryptedKey = encryption.Decrypt(encryptedKey);
            }
            catch { } // I don't want to do anything since decryptedKey is already initialized to an empty string

            return decryptedKey;
        }

        private string GetComponent(string hwClass, string identifier)
        {
            ManagementObjectSearcher mos = new ManagementObjectSearcher("root\\CIMV2", $"SELECT * FROM {hwClass}");
            string component = "";
            foreach(ManagementObject mo in mos.Get())
            {
                component = Convert.ToString(mo[identifier]);
            }
            return component;
        }


        #endregion


    }
}




/*
 * 
 * 1. isFirstLaunch() should run first to see if the EZAuth.key file exists, if returns false, should then trigger an event that requires a key to be input into a form to continue.
 * This will create the file and write the encrypted key to it.
 * 2. If not first launch, MatchLocalSN(dbSN) should be used to match the current local SN to the DB and if it doesn't match, will be required to re-enter the SN
 * 
 */
