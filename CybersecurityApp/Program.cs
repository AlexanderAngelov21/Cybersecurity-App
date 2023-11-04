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
                Console.WriteLine("2. Check open ports on a remote host");
                Console.WriteLine("3. Traceroute");
                Console.WriteLine("4. Exit");
                var choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        Console.Write("\nEnter a website URL to ping: ");
                        var website = Console.ReadLine();
                        PingWebsite(website);
                        break;
                    case "2":
                        Console.Write("\nEnter a remote host IP address to check open ports: ");
                        var ipAddress = Console.ReadLine();
                        CheckOpenPorts(ipAddress);
                        break;
                    case "3":
                        Console.Write("\nEnter the IP address or domain name to trace: ");
                        var traceAddress = Console.ReadLine();
                        TraceRoute(traceAddress);
                     
                        break;
                    case "4":
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
        static void CheckOpenPorts(string ipAddress)
        {
            try
            {
                var portsToCheck = new[] { 80, 443, 22, 3389, 1433 };

                Console.WriteLine($"\nScanning open ports on {ipAddress}");

                foreach (var port in portsToCheck)
                {
                    var client = new TcpClient();

                    try
                    {
                        client.Connect(ipAddress, port);
                        Console.WriteLine($"Port {port} is open");
                    }
                    catch
                    {
                        Console.WriteLine($"Port {port} is closed");
                    }
                    finally
                    {
                        client.Close();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }
        }
        static void TraceRoute(string address)
        {
            try
            {
                var ping = new Ping();
                var maxHops = 30;
                var timeout = 2000;
                var bufferSize = 32;

                Console.WriteLine($"\nTracing route to {address}");

                for (int i = 1; i <= maxHops; i++)
                {
                    var reply = ping.Send(address, timeout, new byte[bufferSize], new PingOptions(i, true));

                    if (reply != null && reply.Status != IPStatus.TtlExpired &&
                        reply.Status != IPStatus.TimedOut)
                    {
                        Console.WriteLine($"Hop {i}: {reply.Address} ({reply.RoundtripTime} ms)");

                        if (reply.Address.ToString() == address)
                        {
                            Console.WriteLine($"\nReached {address} !");
                            break;
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Hop {i}:");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }
        }
    }
}
