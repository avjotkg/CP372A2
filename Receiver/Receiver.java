// receiver protocol notes for ds-ftp (universal receiver behavior; stop-and-wait works without window arg)

// packet types (byte 0):
// 0 = SOT, 1 = DATA, 2 = ACK, 3 = EOT

// packet layout (always exactly 128 bytes):
// type (1) + seq (1) + length (2 big-endian) + payload (124 max)

// sequence rules (mod 128):
// - SOT must be seq=0
// - first DATA expected seq=1
// - receiver tracks expectedseq and accepts only in-order data
// - duplicates/out-of-order are not written; receiver re-acks last in-order seq
// - EOT is accepted and acked; receiver closes output file and exits only after the EOT ack is actually sent

// stop-and-wait receiver behavior:
// - after receiving SOT: set expectedseq=1, lastinorder=0, open output file (once)
// - on DATA:
//   if seq==expectedseq: write payload, ack seq, advance expectedseq
//   else: do not write, re-ack lastinorder
// - on EOT:
//   attempt to ack eot seq
//   if ack was dropped by chaos, do not exit yet (wait for sender retransmit)
//   if ack was actually sent, close output file and exit

// chaos rules (ack loss simulation):
// - receiver drops every rn-th ack (including SOT and EOT acks)
// - use ChaosEngine.shouldDrop(ackCount, rn)
// - ackCount increments for every ack "attempt" (even if dropped)

import java.io.File;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class Receiver
{
    // runtime config
    private InetAddress senderaddr;
    private int senderackport;
    private int rcvdataport;
    private String outputfile;
    private int rn;

    // udp socket (receiver listens on rcv_data_port)
    private DatagramSocket datasock;

    // output stream
    private FileOutputStream out;

    // receiver state
    private boolean handshaked;
    private int expectedseq;
    private int lastinorder;

    // chaos state (1-indexed "intended ack" count)
    private int ackcount;

    public static void main(String[] args)
    {
        Receiver receiver = new Receiver();
        receiver.run(args);
    }

    private void run(String[] args)
    {
        // args:
        // java Receiver <sender_ip> <sender_ack_port> <rcv_data_port> <output_file> <RN>

        if (args == null || args.length < 5)
        {
            printusage();
            return;
        }

        String senderiptext = args[0].trim();
        String senderackporttext = args[1].trim();
        String rcvdataporttext = args[2].trim();
        String outputfiletext = args[3].trim();
        String rntext = args[4].trim();

        if (senderiptext.length() == 0)
        {
            System.out.println("sender_ip is required.");
            return;
        }

        Integer ackport = parseport(senderackporttext, "sender_ack_port");
        if (ackport == null)
        {
            return;
        }

        Integer dataport = parseport(rcvdataporttext, "rcv_data_port");
        if (dataport == null)
        {
            return;
        }

        if (outputfiletext.length() == 0)
        {
            System.out.println("output_file is required.");
            return;
        }

        // validate output file path early (so we dont fail during handshake)
        if (!validateoutputfile(outputfiletext))
        {
            return;
        }

        // rn can be negative; treat it as 0 (no ack loss)
        Integer rnvalue = parseint(rntext, "RN");
        if (rnvalue == null)
        {
            return;
        }

        if (rnvalue < 0)
        {
            System.out.println("RN is negative. treating RN as 0 (no ACK loss).");
            rnvalue = 0;
        }

        try
        {
            senderaddr = InetAddress.getByName(senderiptext);
        }
        catch (Exception ex)
        {
            System.out.println("invalid sender_ip: " + ex.getMessage());
            return;
        }

        senderackport = ackport;
        rcvdataport = dataport;
        outputfile = outputfiletext;
        rn = rnvalue;

        // init state
        handshaked = false;
        expectedseq = 1;
        lastinorder = 0;
        ackcount = 0;

        try
        {
            datasock = new DatagramSocket(rcvdataport);

            // main receive loop (single thread)
            doreceiveloop();
        }
        catch (Exception ex)
        {
            System.out.println("receiver error: " + ex.getMessage());
        }
        finally
        {
            // clean close
            try
            {
                if (out != null)
                {
                    out.close();
                }
            }
            catch (Exception ex)
            {
                // ignore
            }

            try
            {
                if (datasock != null)
                {
                    datasock.close();
                }
            }
            catch (Exception ex)
            {
                // ignore
            }
        }
    }

    private void doreceiveloop() throws Exception
    {
        while (true)
        {
            DSPacket p = receivepacket();
            if (p == null)
            {
                continue;
            }

            byte type = p.getType();
            int seq = p.getSeqNum() % 128;

            if (type == DSPacket.TYPE_SOT)
            {
                handlesot(seq);
            }
            else if (type == DSPacket.TYPE_DATA)
            {
                handledatastopandwait(p, seq);
            }
            else if (type == DSPacket.TYPE_EOT)
            {
                boolean done = handleeot(seq);
                if (done)
                {
                    return;
                }
            }
            else
            {
                // ignore unknown packets
            }
        }
    }

    // handshake: on sot seq=0, ack 0 and set expectedseq=1
    private void handlesot(int seq) throws Exception
    {
        System.out.println("received SOT seq=" + seq);

        if (seq != 0)
        {
            // ignore malformed sot
            return;
        }

        if (!handshaked)
        {
            // open output file once on first successful sot
            out = new FileOutputStream(outputfile, false);

            handshaked = true;
            expectedseq = 1;
            lastinorder = 0;

            System.out.println("handshake established. expectedseq set to 1.");
        }
        else
        {
            // repeated sot due to lost ack is ok
            System.out.println("duplicate SOT received. re-acking.");
        }

        sendack(0);
    }

    // stop-and-wait data handling
    private void handledatastopandwait(DSPacket p, int seq) throws Exception
    {
        if (!handshaked)
        {
            // data before handshake: ignore
            return;
        }

        int len = p.getLength();

        if (seq == expectedseq)
        {
            System.out.println("received DATA seq=" + seq + " len=" + len + " expected=" + expectedseq + " (written)");

            // write exactly length bytes
            byte[] payload = p.getPayload();
            if (payload != null && payload.length > 0)
            {
                out.write(payload, 0, payload.length);
            }

            lastinorder = seq;
            expectedseq = (expectedseq + 1) % 128;

            sendack(seq);
        }
        else
        {
            // duplicate or out-of-order (stop-and-wait expects only duplicates realistically)
            System.out.println("received DATA seq=" + seq + " len=" + len + " expected=" + expectedseq + " (duplicate/out-of-order)");

            // resend ack for last in-order packet
            sendack(lastinorder);
        }
    }

    // teardown: on eot, ack and exit only if the ack was actually sent (not dropped)
    private boolean handleeot(int seq) throws Exception
    {
        if (!handshaked)
        {
            // eot before handshake: ignore
            return false;
        }

        System.out.println("received EOT seq=" + seq);

        boolean sent = sendack(seq);

        if (sent)
        {
            // only close after the eot ack is actually sent
            try
            {
                if (out != null)
                {
                    out.close();
                    out = null;
                }
            }
            catch (Exception ex)
            {
                // ignore
            }

            System.out.println("transfer complete. receiver exiting.");
            return true;
        }
        else
        {
            System.out.println("eot ack was dropped. waiting for sender to retransmit eot...");
            return false;
        }
    }

    // udp helpers

    private DSPacket receivepacket()
    {
        try
        {
            byte[] buf = new byte[DSPacket.MAX_PACKET_SIZE];
            DatagramPacket dp = new DatagramPacket(buf, buf.length);

            datasock.receive(dp);

            // parse raw 128 bytes into dspacket
            return new DSPacket(dp.getData());
        }
        catch (Exception ex)
        {
            return null;
        }
    }

    private void sendpacket(DSPacket packet, InetAddress addr, int port) throws Exception
    {
        byte[] bytes = packet.toBytes();

        DatagramPacket dp = new DatagramPacket(bytes, bytes.length, addr, port);
        datasock.send(dp);
    }

    // returns true if ack was actually sent, false if dropped (or failed to send)
    private boolean sendack(int seq)
    {
        // increment ackcount for every ack attempt (even if dropped)
        ackcount++;

        boolean drop = ChaosEngine.shouldDrop(ackcount, rn);

        if (drop)
        {
            System.out.println("sending ACK seq=" + seq + " (dropped by chaos) ackcount=" + ackcount + " rn=" + rn);
            return false;
        }

        System.out.println("sending ACK seq=" + seq + " ackcount=" + ackcount + " rn=" + rn);

        try
        {
            DSPacket ack = new DSPacket(DSPacket.TYPE_ACK, seq, null);
            sendpacket(ack, senderaddr, senderackport);
            return true;
        }
        catch (Exception ex)
        {
            System.out.println("warning: failed to send ACK seq=" + seq + " : " + ex.getMessage());
            return false;
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

    private Integer parseint(String text, String name)
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

        return v;
    }

    private boolean validateoutputfile(String path)
    {
        try
        {
            File f = new File(path);

            if (f.exists() && f.isDirectory())
            {
                System.out.println("output_file is a directory, not a file.");
                return false;
            }

            File parent = f.getAbsoluteFile().getParentFile();
            if (parent != null)
            {
                if (!parent.exists())
                {
                    System.out.println("output_file parent directory does not exist: " + parent.getPath());
                    return false;
                }

                if (!parent.canWrite())
                {
                    System.out.println("output_file parent directory is not writable: " + parent.getPath());
                    return false;
                }
            }

            if (f.exists() && !f.canWrite())
            {
                System.out.println("output_file is not writable: " + path);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            System.out.println("output_file is invalid: " + ex.getMessage());
            return false;
        }
    }

    private void printusage()
    {
        System.out.println("usage:");
        System.out.println("  java Receiver <sender_ip> <sender_ack_port> <rcv_data_port> <output_file> <RN>");
    }
}