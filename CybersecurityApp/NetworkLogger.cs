using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CybersecurityApp
{
    class NetworkLogger
    {
        private string logFilePath;
        public NetworkLogger(string logFilePath)
        {
            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            this.logFilePath = Path.Combine(desktopPath, logFilePath);
        }
        public void LogEvent(string eventType, string eventMessage)
        {
            string logEntry = $"{DateTime.Now} | {eventType} | {eventMessage}";
            File.AppendAllText(logFilePath, $"{logEntry}\n");
        }
    }
}
