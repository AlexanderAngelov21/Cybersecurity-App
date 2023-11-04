﻿using System;
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
                Console.WriteLine("4. DNS Lookup");
                Console.WriteLine("5. WHOIS Lookup");
                Console.WriteLine("6. Scan local network for live hosts");
                Console.WriteLine("7. Scan for open ports with start and end port");
                Console.WriteLine("8. Public address check");
                Console.WriteLine("9. SSL/TLS Certificate Validation");
                Console.WriteLine("10. HTTP Header Analysis");
                Console.WriteLine("11. Exit");
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
                        Console.Write("\nEnter a domain name to perform DNS lookup: ");
                        var hostname = Console.ReadLine();
                        DnsLookup(hostname);
                        break;
                    case "5":
                        Console.Write("\nEnter a domain name to perform WHOIS lookup: ");
                        var domain = Console.ReadLine();
                        WhoisLookup(domain);
                        break;
                    case "6":
                        Console.WriteLine("\nScanning local network for live hosts...");
                        ScanLocalNetwork();                   
                        break;
                    case "7":
                        Console.Write("\nEnter a remote host IP address to check open ports: ");
                        var remoteIpAddress = Console.ReadLine();
                        Console.Write("Enter the starting port: ");
                        int startPort = int.Parse(Console.ReadLine());
                        Console.Write("Enter the ending port: ");
                        int endPort = int.Parse(Console.ReadLine());
                        CheckOpenPorts(remoteIpAddress, startPort, endPort);
                        break;
                    case "8":
                        GetPublicIPAddress();
                        break;
                    case "9":
                        Console.Write("\nEnter a website URL to validate SSL/TLS certificate: ");
                        var websiteCheck = Console.ReadLine();
                        ValidateSSLCertificate(websiteCheck);
                        break;
                    case "10":
                        Console.Write("\nEnter a website URL to analyze HTTP headers: ");
                        var websiteToAnalyze = Console.ReadLine();
                        AnalyzeHttpHeaders(websiteToAnalyze);
                        break;
                    case "11":
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
        static void DnsLookup(string hostname)
        {
            try
            {
                var ipAddresses = Dns.GetHostAddresses(hostname);

                Console.WriteLine($"\nIP addresses for {hostname}:");

                foreach (var ipAddress in ipAddresses)
                {
                    Console.WriteLine(ipAddress);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }
        }
        static void WhoisLookup(string domain)
        {
            try
            {
                var whoisServer = "whois.verisign-grs.com";
                var tcpClient = new TcpClient(whoisServer, 43);
                var networkStream = tcpClient.GetStream();
                var streamWriter = new StreamWriter(networkStream) { AutoFlush = true };
                var streamReader = new StreamReader(networkStream);

                streamWriter.WriteLine(domain);

                var response = "";
                string line;
                while ((line = streamReader.ReadLine()) != null)
                {
                    response += line + "\n";
                }

                Console.WriteLine($"\nWHOIS information for {domain}:\n{response}");

                tcpClient.Close();
                streamWriter.Close();
                streamReader.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }
        }
        static void ScanLocalNetwork()
        {
            try
            {
                var localIPAddress = GetLocalIPAddress();
                var subnetAddress = GetSubnetAddress(localIPAddress);

                Console.WriteLine($"\nScanning local network (Subnet: {subnetAddress}) for live hosts...");

                var liveHosts = new List<IPAddress>();

                for (int i = 1; i <= 255; i++)
                {
                    var ping = new Ping();
                    var ip = $"{subnetAddress}.{i}";

                    var reply = ping.Send(ip, 100); // Adjust timeout as required

                    if (reply != null && reply.Status == IPStatus.Success)
                    {
                        Console.WriteLine($"Host {ip} is up");
                        liveHosts.Add(reply.Address);
                    }
                }

                Console.WriteLine($"\nFound {liveHosts.Count} live hosts:");

                foreach (var host in liveHosts)
                {
                    Console.WriteLine(host);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }
        }
        static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());

            foreach (var ipAddress in host.AddressList)
            {
                if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ipAddress.ToString();
                }
            }

            throw new Exception("No network adapters with an IPv4 address found.");
        }

        static string GetSubnetAddress(string ipAddress)
        {
            return string.Join(".", ipAddress.Split('.').Take(3));
        }
        static void CheckOpenPorts(string ipAddress, int startPort, int endPort)
        {
            try
            {
                Console.WriteLine($"\nScanning open ports on {ipAddress} in the range {startPort}-{endPort}");

                for (int port = startPort; port <= endPort; port++)
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
        static async Task GetPublicIPAddress()
        {
            using (HttpClient client = new HttpClient())
            {
                string response = await client.GetStringAsync("https://api.ipify.org?format=text");
                Console.WriteLine($"Your Public IP Address is: {response}");
            }
        }
        static void ValidateSSLCertificate(string website)
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    HttpResponseMessage response = client.GetAsync($"https://{website}").Result;

                    if (response.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"\nSSL/TLS Certificate for {website} is valid.");
                    }
                    else
                    {
                        Console.WriteLine($"\nSSL/TLS Certificate for {website} is not valid or the website is unreachable.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }
        }
        static async Task AnalyzeHttpHeaders(string website)
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    HttpResponseMessage response = await client.GetAsync($"https://{ website}");

                    if (response.IsSuccessStatusCode)
                    {
                        Console.WriteLine("\nHTTP Headers for " + website + ":");
                        foreach (var header in response.Headers)
                        {
                            Console.WriteLine(header.Key + ": " + string.Join(", ", header.Value));
                        }
                    }
                    else
                    {
                        Console.WriteLine($"\nFailed to retrieve HTTP headers for {website}. Status code: {response.StatusCode}");
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
