using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using PcapDotNet.Core;
using PcapDotNet.Core.Extensions;
using System.Diagnostics;
using SharpPcap;
using PacketDotNet;


namespace CybersecurityApp
{
  
    class Program
    {
        static void Main(string[] args)
        {
           
            Console.WriteLine("Welcome to the Cybersecurity App!");

            while (true)
            {
                Console.WriteLine("\nPlease select an option:");
                Console.WriteLine("1. Ping a website");
                Console.WriteLine("2. Exit");
                var choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        Console.Write("\nEnter a website URL to ping: ");
                        var website = Console.ReadLine();
                        PingWebsite(website);
                        break;
                 
                    case "2":
                        Console.WriteLine("\nExiting...");
                
                        return;         
                    default:
                        Console.WriteLine("\nInvalid choice! Please try again.");
                        break;
                }
            }
        }
      
        static void PingWebsite(string website)
        {
            try
            {
                var ping = new Ping();

                var reply = ping.Send(website);

                if (reply != null && reply.Status == IPStatus.Success)
                {
                    Console.WriteLine($"\n{website} is reachable. Roundtrip time: {reply.RoundtripTime} ms");
                }
                else
                {
                    Console.WriteLine($"\n{website} is unreachable.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }
        }
    }
}
