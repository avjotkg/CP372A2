// sender protocol notes for ds-ftp stop-and-wait (rdt 3.0)

// packet types (byte 0):
// 0 = SOT (start of transmission)
// 1 = DATA (file bytes)
// 2 = ACK (acknowledgment)
// 3 = EOT (end of transmission)

// packet layout (always exactly 128 bytes on the wire):
// byte 0   : type
// byte 1   : seq num (mod 128)
// bytes 2-3: length (big-endian short)
// bytes 4-127: payload (max 124 bytes)

// sequence rules (mod 128):
// - SOT always uses seq = 0
// - first DATA uses seq = 1
// - EOT uses seq = (last data seq + 1) mod 128
// - comparisons respect wrap-around (we keep everything mod 128)

// stop-and-wait sender behavior:
// - send one packet (SOT, then each DATA, then EOT)
// - wait for the specific ACK (type=ACK, seq matches)
// - on timeout: retransmit the same packet (same seq)
// - only advance seq after receiving the correct ACK

// timeout rule:
// - use DatagramSocket.setSoTimeout(timeout_ms)

// critical failure rule:
// - if 3 consecutive timeouts occur for the same expected ack (no progress):
//   print "Unable to transfer file." and terminate immediately

// chaos rules:
// - receiver may drop every rn-th ack (including SOT and EOT acks)
// - sender must tolerate lost acks using timeouts + retransmissions

// cli (stop-and-wait):
// java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> <input_file> <timeout_ms>
// if an extra [window_size] is provided, gbn is not implemented here (partner will extend)

import java.io.File;
import java.io.FileInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class Sender
{
    // runtime config
    private InetAddress rcvaddr;
    private int rcvdataport;
    private int senderackport;
    private String inputfile;
    private int timeoutms;

    // udp socket (sender listens for acks on sender_ack_port)
    private DatagramSocket sock;

    // timing
    private long startms;

    public static void main(String[] args)
    {
        Sender sender = new Sender();
        sender.run(args);
    }

    private void run(String[] args)
    {
        // args:
        // 0 rcv_ip
        // 1 rcv_data_port
        // 2 sender_ack_port
        // 3 input_file
        // 4 timeout_ms
        // [5 window_size] optional (gbn not implemented in this file)

        if (args == null || args.length < 5)
        {
            printusage();
            return;
        }

        if (args.length > 5)
        {
            System.out.println("gbn mode detected (window_size provided), but gbn is not implemented in this sender yet.");
            System.out.println("run without window_size for stop-and-wait.");
            return;
        }

        String rcviptext = args[0].trim();
        String rcvdataporttext = args[1].trim();
        String senderackporttext = args[2].trim();
        String inputfiletext = args[3].trim();
        String timeoutmstext = args[4].trim();

        if (rcviptext.length() == 0)
        {
            System.out.println("rcv_ip is required.");
            return;
        }

        Integer rcvport = parseport(rcvdataporttext, "rcv_data_port");
        if (rcvport == null)
        {
            return;
        }

        Integer ackport = parseport(senderackporttext, "sender_ack_port");
        if (ackport == null)
        {
            return;
        }

        Integer tmo = parsenonnegativeint(timeoutmstext, "timeout_ms");
        if (tmo == null)
        {
            return;
        }

        if (tmo <= 0)
        {
            System.out.println("timeout_ms must be > 0.");
            return;
        }

        if (inputfiletext.length() == 0)
        {
            System.out.println("input_file is required.");
            return;
        }

        File f = new File(inputfiletext);
        if (!f.exists() || !f.isFile())
        {
            System.out.println("input_file does not exist: " + inputfiletext);
            return;
        }

        if (!f.canRead())
        {
            System.out.println("input_file is not readable: " + inputfiletext);
            return;
        }

        // store config
        rcvdataport = rcvport;
        senderackport = ackport;
        inputfile = inputfiletext;
        timeoutms = tmo;

        try
        {
            rcvaddr = InetAddress.getByName(rcviptext);
        }
        catch (Exception ex)
        {
            System.out.println("invalid rcv_ip: " + ex.getMessage());
            return;
        }

        // main protocol run
        try
        {
            sock = new DatagramSocket(senderackport);
            sock.setSoTimeout(timeoutms);

            // start timer at first SOT send
            startms = -1;

            dostopandwait();
        }
        catch (Exception ex)
        {
            System.out.println("sender error: " + ex.getMessage());
        }
        finally
        {
            try
            {
                if (sock != null)
                {
                    sock.close();
                }
            }
            catch (Exception ex)
            {
                // ignore
            }
        }
    }

    private void dostopandwait() throws Exception
    {
        // phase 1: handshake
        boolean ok = dohandshake();
        if (!ok)
        {
            return;
        }

        // phase 2: data transfer
        int lastdataseq = dostreamfile();
        if (lastdataseq < 0)
        {
            // critical failure already printed
            return;
        }

        // phase 3: teardown
        ok = doteardown(lastdataseq);
        if (!ok)
        {
            return;
        }
    }

    // handshake: send sot seq=0, wait for ack seq=0
    private boolean dohandshake() throws Exception
    {
        int expectedackseq = 0;
        int timeoutcount = 0;

        DSPacket sot = new DSPacket(DSPacket.TYPE_SOT, 0, null);

        while (true)
        {
            if (startms < 0)
            {
                // timer starts at sending sot (first send only)
                startms = System.currentTimeMillis();
            }

            System.out.println("sending SOT seq=0");
            sendpacket(sot);

            DSPacket ack = receiveack(expectedackseq);
            if (ack != null)
            {
                System.out.println("received ACK seq=" + ack.getSeqNum() + " (SOT)");
                return true;
            }

            timeoutcount++;

            System.out.println("timeout waiting for ACK seq=" + expectedackseq + " (count=" + timeoutcount + ")");

            if (timeoutcount >= 3)
            {
                System.out.println("Unable to transfer file.");
                return false;
            }
        }
    }

    // sends the file as stop-and-wait data packets; returns last data seq, or -1 on failure
    private int dostreamfile() throws Exception
    {
        File f = new File(inputfile);

        // empty file case: no data packets, last data seq stays 0 (so eot seq becomes 1)
        if (f.length() == 0)
        {
            System.out.println("input file is empty (0 bytes). sending no DATA packets.");
            return 0;
        }

        FileInputStream in = null;

        int seq = 1;
        int lastdataseq = 0;

        try
        {
            in = new FileInputStream(f);

            byte[] buffer = new byte[DSPacket.MAX_PAYLOAD_SIZE];

            while (true)
            {
                int bytesread = readchunk(in, buffer);
                if (bytesread < 0)
                {
                    break;
                }

                byte[] payload = new byte[bytesread];
                System.arraycopy(buffer, 0, payload, 0, bytesread);

                DSPacket data = new DSPacket(DSPacket.TYPE_DATA, seq, payload);

                boolean ok = sendandwaitforack(data, seq);
                if (!ok)
                {
                    return -1;
                }

                lastdataseq = seq;
                seq = (seq + 1) % 128;
            }
        }
        finally
        {
            try
            {
                if (in != null)
                {
                    in.close();
                }
            }
            catch (Exception ex)
            {
                // ignore
            }
        }

        return lastdataseq;
    }

    // reads up to 124 bytes, but tries hard to fill the chunk unless EOF is reached
    // returns:
    // -1 if EOF and no bytes read
    // 1..124 for payload size
    private int readchunk(FileInputStream in, byte[] buffer) throws Exception
    {
        int total = 0;

        while (total < buffer.length)
        {
            int n = in.read(buffer, total, buffer.length - total);

            if (n < 0)
            {
                break;
            }

            if (n == 0)
            {
                // should not happen for FileInputStream, but dont loop forever
                break;
            }

            total += n;

            // if we filled the payload, stop
            if (total == buffer.length)
            {
                break;
            }
        }

        if (total == 0)
        {
            return -1;
        }

        return total;
    }

    // teardown: send eot seq=(last data + 1) mod 128, wait for ack
    private boolean doteardown(int lastdataseq) throws Exception
    {
        int eotseq = (lastdataseq + 1) % 128;

        DSPacket eot = new DSPacket(DSPacket.TYPE_EOT, eotseq, null);

        int timeoutcount = 0;

        while (true)
        {
            System.out.println("sending EOT seq=" + eotseq);
            sendpacket(eot);

            DSPacket ack = receiveack(eotseq);
            if (ack != null)
            {
                System.out.println("received ACK seq=" + ack.getSeqNum() + " (EOT)");

                long endms = System.currentTimeMillis();
                double seconds = (endms - startms) / 1000.0;

                System.out.printf("Total Transmission Time: %.2f seconds%n", seconds);

                return true;
            }

            timeoutcount++;

            System.out.println("timeout waiting for ACK seq=" + eotseq + " (count=" + timeoutcount + ")");

            if (timeoutcount >= 3)
            {
                System.out.println("Unable to transfer file.");
                return false;
            }
        }
    }

    // send one packet, wait for its ack, handle timeouts and critical failure
    private boolean sendandwaitforack(DSPacket packet, int expectedackseq) throws Exception
    {
        int timeoutcount = 0;

        while (true)
        {
            System.out.println("sending DATA seq=" + packet.getSeqNum() + " len=" + packet.getLength());
            sendpacket(packet);

            DSPacket ack = receiveack(expectedackseq);
            if (ack != null)
            {
                System.out.println("received ACK seq=" + ack.getSeqNum());
                return true;
            }

            timeoutcount++;

            System.out.println("timeout waiting for ACK seq=" + expectedackseq + " (count=" + timeoutcount + ")");

            if (timeoutcount >= 3)
            {
                System.out.println("Unable to transfer file.");
                return false;
            }
        }
    }

    // send helpers

    private void sendpacket(DSPacket packet) throws Exception
    {
        byte[] bytes = packet.toBytes();

        DatagramPacket dp = new DatagramPacket(bytes, bytes.length, rcvaddr, rcvdataport);
        sock.send(dp);
    }

    // receive helpers

    private DSPacket receivepacket() throws Exception
    {
        byte[] buf = new byte[DSPacket.MAX_PACKET_SIZE];
        DatagramPacket dp = new DatagramPacket(buf, buf.length);

        sock.receive(dp);

        // parse raw 128 bytes into dspacket
        return new DSPacket(dp.getData());
    }

    // ack receive helpers

    private DSPacket receiveack(int expectedseq)
    {
        // keep receiving until we get the ack we want, or timeout occurs
        // on timeout, return null so caller can retransmit

        while (true)
        {
            try
            {
                DSPacket p = receivepacket();

                if (p.getType() != DSPacket.TYPE_ACK)
                {
                    // ignore non-ack packets
                    continue;
                }

                int seq = p.getSeqNum() % 128;

                if (seq != expectedseq)
                {
                    // ignore wrong ack (does not advance progress)
                    continue;
                }

                return p;
            }
            catch (java.net.SocketTimeoutException ex)
            {
                return null;
            }
            catch (Exception ex)
            {
                // ignore weird packet and keep listening until timeout
            }
        }
    }

    // validation helpers

    private Integer parseport(String text, String name)
    {
        Integer v = parsenonnegativeint(text, name);
        if (v == null)
        {
            return null;
        }

        if (v < 1 || v > 65535)
        {
            System.out.println(name + " must be 1 to 65535.");
            return null;
        }

        return v;
    }

    private Integer parsenonnegativeint(String text, String name)
    {
        if (text == null)
        {
            text = "";
        }

        text = text.trim();

        if (text.length() == 0)
        {
            System.out.println(name + " is required.");
            return null;
        }

        int v;

        try
        {
            v = Integer.parseInt(text);
        }
        catch (Exception ex)
        {
            System.out.println(name + " must be a number.");
            return null;
        }

        if (v < 0)
        {
            System.out.println(name + " must be 0 or more.");
            return null;
        }

        return v;
    }

    private void printusage()
    {
        System.out.println("usage:");
        System.out.println("  java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> <input_file> <timeout_ms> [window_size]");
        System.out.println("notes:");
        System.out.println("  omit window_size for stop-and-wait (implemented here).");
        System.out.println("  provide window_size for gbn (partner will extend).");
    }
}