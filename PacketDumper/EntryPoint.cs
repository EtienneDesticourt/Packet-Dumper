using RGiesecke.DllExport;

namespace PacketDumper
{
        internal class EntryPoint
        {
                [DllExport("Main")]
                internal static void Main()
                {
                        PacketSnifferHook.Install(@"E:\Users\Etienne2\Desktop\packetlog.txt");
                }
        }
}