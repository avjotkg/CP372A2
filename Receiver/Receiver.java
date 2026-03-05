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

// note (gbn):
// - this receiver is written to be "universal" (no window arg required)

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

    // mode flags (stop-and-wait now; can enable gbn later)
    private boolean gbnmode;
    private int windowsize;


    //GBN buffering
    private boolean[] buffered;
    private byte[][] bufferdata;
    private int[] bufferlen;

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

        buffered = new boolean[128];
        bufferdata = new byte[128][];
        bufferlen = new int [128];

        // stop-and-wait is default
        gbnmode = true;
        windowsize = 64;

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
                handledatapacket(p, seq);
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

    // this router keeps receiver "universal"
    // - right now it always behaves as stop-and-wait
    private void handledatapacket(DSPacket p, int seq) throws Exception
    {
        
        if (gbnmode)
        {
            // jason: implement gbn receive here later (buffering + cumulative acks)
            handledatagobackn(p, seq);
        }
        else
        {
            handledatastopandwait(p, seq);
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

            //Clear old buffrd packets
            for (int i = 0; i < 128; i ++){
                buffered[i] = false;
                bufferdata[i] = null;
                bufferlen[i] = 0;
            }

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
                out.write(payload, 0, len);
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

    // jason: go-back-n receiver logic here
    private void handledatagobackn(DSPacket p, int seq) throws Exception
    {
        if (!handshaked){
            return;
        }

        int len = p.getLength();

        //for if the packet is inside reciever window -> buffer it (if not already)
        if (inReceiveWindow(expectedseq, seq)){
            if (!buffered[seq]){
                //only store the len of bytes

                byte[] payload = p.getPayload();
                byte[] copy = new byte[len];
                if (len > 0 && payload != null){
                    System.arraycopy(payload, 0, copy, 0, len);
                }

                //Set respective arrays to indicate buf.
                buffered[seq] = true;
                bufferdata[seq] = copy;
                bufferlen[seq] = len;


                System.out.println("receievd data seq =" + seq + " len = " +  len + " (buffered) expected = " + expectedseq);
                

            } else {
                System.out.println("receievd data seq =" + seq + " len = "+ len + " (duplicate duffered) expected = " + expectedseq);
            }
            //Now, in order and contiguous send the packets from the expected seq onward
            while (buffered[expectedseq]){
                byte[] data = bufferdata[expectedseq];
                int blen = bufferlen[expectedseq];

                if (data != null && blen > 0){
                    out.write(data,0,blen);
                }

                buffered[expectedseq] = false;
                bufferdata[expectedseq] = null;
                bufferlen[expectedseq] = 0;

                lastinorder = expectedseq;
                expectedseq = (expectedseq + 1) % 128;

            }
            //Send the cumultive ACK 
            sendack(lastinorder);
        } else {
            System.out.println("recieved DATA seq=" + seq +  " len = " + len + " (out of window, discarded) expected" + expectedseq + " lastinorder=" + lastinorder);
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

        //for GBN only accept EOT when all prior data has been delievered

        if (gbnmode){
            if (seq != expectedseq){
                System.out.println("EOT OOO (Seq = " + seq + " expected="+ expectedseq + "). reacking lastinorder= " + lastinorder);
                sendack(lastinorder);
                return false;
            }
        }


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

    private int forwardDistance(int expected, int seq){
        return (seq-expected + 128) % 128; 
    }

    private boolean inReceiveWindow(int expected, int seq){
        int d = forwardDistance(expected, seq);
        return d >= 0 && d < windowsize;
    }
}
