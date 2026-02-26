using System;

namespace Xdows_Security
{
    public class FileDownloadCompletedEventArgs(string fileId, string fileName, string filePath) : EventArgs
    {
        public string FileId { get; } = fileId;
        public string FileName { get; } = fileName;
        public string FilePath { get; } = filePath;
    }
}
