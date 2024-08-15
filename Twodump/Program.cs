
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Spectre.Console;
using Twodump;

var fileDataBuffer = new byte[0x1000000];
using var listener = new TcpListener(IPAddress.Any, 8126);
listener.Start();

AnsiConsole.MarkupLine("Now listening on port [white bold]8126[/] for connections.");

while (true)
{
    var socket = listener.AcceptTcpClient();
    AnsiConsole.Progress()
        .Columns(
            new TaskDescriptionColumn(),
            new ProgressBarColumn(),
            new PercentageColumn(),
            new TransferSpeedColumn(),
            new DownloadedColumn(),
            new RemainingTimeColumn(),
            new SpinnerColumn())
        .Start(ctx =>
        {
            var stream = socket.GetStream();
            using (stream)
            {
                var dumpInfo = (stackalloc DumpInfo[1]);
                var filenameBuffer = (stackalloc byte[260]);
                var fileData = fileDataBuffer.AsSpan();

                while ((dumpInfo[0].Flags & FileFlags.BeginTransfer) == 0)
                    stream.ReadExactly(MemoryMarshal.Cast<DumpInfo, byte>(dumpInfo));

                while (socket.Connected)
                {
                    ctx.Refresh();

                    stream.ReadExactly(MemoryMarshal.Cast<DumpInfo, byte>(dumpInfo));
                    var info = dumpInfo[0];
                    if ((info.Flags & FileFlags.EndTransfer) != 0)
                        break;

                    var filenameData = filenameBuffer[..(int)info.FilenameLength];
                    stream.ReadExactly(filenameData);

                    var filename = Encoding.UTF8.GetString(filenameData);
                    if (filename.Length > 1 && filename[1] == ':')
                        filename = $"{filename[0]}x{filename[2..]}";

                    if (info.Attributes.HasFlag(FileAttributes.Directory) ||
                        info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                        filename.EndsWith('\\'))
                    {
                        Directory.CreateDirectory(filename);
                    }
                    else
                    {
                        if ((info.Flags & FileFlags.FailedToRead) != 0)
                        {
                            ctx.AddTask($"[red bold]Failed to transfer {filename}[/]", false, info.FileSize);
                            continue;
                        }

                        var task = ctx.AddTask($"[white bold]{filename}[/]", true, info.FileSize);

                        // Just for good measure
                        var fullPath = Path.GetFullPath(filename);
                        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);

                        using var fs = File.OpenWrite(filename);
                        var remaining = info.FileSize;
                        while (remaining != 0)
                        {
                            var current = (int)Math.Min(remaining, (ulong)fileData.Length);
                            var currentBuffer = fileData[..current];
                            stream.ReadExactly(currentBuffer);
                            fs.Write(currentBuffer);
                            remaining -= (uint)current;

                            task.Increment(current);
                        }

                        task.StopTask();

                        File.SetCreationTime(filename, DateTime.FromFileTime(info.LastWriteTime));
                    }
                }

                ctx.Refresh();
            }
        });

    var result =
        AnsiConsole.Confirm("[green bold]Finished[/] [white bold]transferring files![/] Do you want to exit?");

    if (result)
        break;
}

listener.Stop();
return 0;

namespace Twodump
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public readonly struct DumpInfo
    {
        private const int FileAttributeBitCount = 18;
        private const int FileAttributeMask = (1 << FileAttributeBitCount) - 1;

        private readonly uint _flags;
        public readonly long LastWriteTime; // FILETIME
        public readonly ulong FileSize;
        public readonly uint FilenameLength;

        public FileAttributes Attributes => (FileAttributes)(_flags & FileAttributeMask);
        public FileFlags Flags => (FileFlags)(_flags >> FileAttributeBitCount);
    }

    [Flags]
    public enum FileFlags : uint
    {
        BeginTransfer = 0b1,
        EndTransfer = 0b10,
        FailedToRead = 0b100
    }
}