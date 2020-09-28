/*--------------------------------------------------------

1. Name / Date:
Justin Zhang 4/19/2020

2. Java version used, if not the official version for the class:

12.0.2

3. Precise command-line compilation examples / instructions:


navigate to directory containing this java file then run the following command to compile
make sure gson-2.8.2.jar file is in the same directory
> javac -cp "gson-2.8.2.jar" Blockchain.java


4. Precise examples / instructions to run this program:

navigate to directory containing this java file
start processes in order from 0 to 2
a. Enter the following command to start process 0
> java -cp ".:gson-2.8.2.jar" Blockchain

b. Enter the following command to start process 1
> java -cp ".:gson-2.8.2.jar" Blockchain 1

c. Enter the following command to start process 2
> java -cp ".:gson-2.8.2.jar" Blockchain 2

after all Unverified blocks have been solved.
Type "C" to see how many blocks each processor has verified
Type "L" to see records of blockchain
Type "R <fileName>" to read another .txt file for unverified block

5. List of files needed for running the program.

 Blockchain.java
 gson-2.8.2.jar
 BlockInput0.txt
 BlockInput1.txt
 BlockInput2.txt

6. Notes:
Did not complete method that verifies the entire blockchain
The "R" functionality is a little buggy. Displaying things out of order when run.
May have to coordinate process better.


----------------------------------------------------------*/

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class Blockchain {
    static String serverName = "localhost"; //string for server name, we are using localhost
    static KeyPair keyPair;                 //holds the private/public key for the process
    static PublicKey[] publicKeys = new PublicKey[3];       //array holding public key of all three processes
    static ArrayList<BlockRecord> blockchain = new ArrayList<>();   //holds blockrecord of verified blockchain
    static String file;     //.txt input file which holds provided blocks
    static int numProcesses = 3;        //we have a total of 3 processes
    static int PID = 0; // default process ID. could change depending on terminal input

    public void MultiSend (boolean key, boolean unverifiedBlock){ //multicast data to all processes
        Socket sock;        //declare server socket
        PrintStream toServer;   //instantiate printstream

        if (key){   //if true, send key to all processes
            try {
                for (int i = 0; i < numProcesses; i++) { //looping through num of processes
                    sock = new Socket(serverName, Ports.KeyServerPortBase + i); //setting socket for each process
                    toServer = new PrintStream(sock.getOutputStream()); //instantiating printstream
                    toServer.println(PID);      //sending process ID, for indexing array
                    //send public key in string form
                    toServer.println(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
                    System.out.println("Sending public key " + " to Process " + i);
                    toServer.flush();   //flush buffer
                    sock.close();       //close socket
                }
                Thread.sleep(1000); // wait for keys to arrive at each process
            }catch (Exception e) {e.printStackTrace();}
        }


        if (unverifiedBlock){   //if true send unverified blocks to each process
            try{
                Gson gson = new Gson();     //google gson library for json object manipulation
                String json;
                System.out.println("Reading from file: " + file);
                //instantiate a BlockUtility object to create BlockRecord
                BlockUtility createBlock = new BlockUtility(file);
                ArrayList<BlockRecord> blockRecords = createBlock.create(); //putting BlockRecord into ArrayList
                int numBlocks = blockRecords.size();    //this lets server know how many records are coming

                for(int i=0; i< numProcesses; i++){// send unverified blocks to each process
                    sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i); //instantiate sockets
                    toServer = new PrintStream(sock.getOutputStream()); //instantiating printstream


                    toServer.println(numBlocks); //this lets server know how many records are coming

                    for (BlockRecord block: blockRecords){
                        json = gson.toJson(block);  //marshalling BlockRecord as json
                        toServer.println(json); //send to server
                    }

                    toServer.flush();
                    sock.close();
                }
            }catch (Exception x) {x.printStackTrace ();}
        }

    }

    public static void consoleOptions(){
        //Header to print out for additional functionalities
        System.out.println("\nFunctionalities:");
        System.out.println("\"R <filename>\": Read in additional records from file");
        System.out.println("\"C\": Show how many blocks each process verified");
        System.out.println("\"L\": List out blockchain records.");
    }
    public static BlockRecord createGenesis() {
        /**
        This creates the first block of the blockchain, aka the dummy block
         */
        BlockRecord genesis = new BlockRecord();
        try {
            String line = "Justin Zhang 1990.10.21 630-777-911 StudyTooMuch GetSomeSleep IceCream";
            String[] sub = line.split("\\s");

            genesis.setBlockNumber(0);
            genesis.setPreviousHash("noPreviousHash");
            genesis.setWinningHash("noPreviousWinningHash");
            String blockID =  new String(UUID.randomUUID().toString()); //use UUID to string as blockID
            genesis.setBlockID(blockID);
            //signed blockID in byte form
            byte signedBlockIDbytes[] = KeyTools.signData(blockID.getBytes(), Blockchain.keyPair.getPrivate());
            //base64 encoding of blockID into string form
            String signedBlockID = Base64.getEncoder().encodeToString(signedBlockIDbytes);
            genesis.setSignedBlockID(signedBlockID);
            genesis.setCreatorProcessID(String.valueOf(Blockchain.PID));
            genesis.setUUID(UUID.randomUUID());
            Date date = new Date();
            String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
            String TimeStampString = T1 + "." + Blockchain.PID;
            genesis.setTimeStamp(TimeStampString);

            genesis.setFname(sub[0]);
            genesis.setLname(sub[1]);
            genesis.setDOB(sub[2]);
            genesis.setSSNum(sub[3]);
            genesis.setDiag(sub[4]);
            genesis.setTreat(sub[5]);
            genesis.setRx(sub[6]);

            genesis.setData(line);

            //hashing the raw data and store it as SHA256 hash
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(line.getBytes());
            byte bytes[] = messageDigest.digest();
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < bytes.length; i++) {        //iterating through the bytes to turn it into hex values
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            String SHA256String = sb.toString();        //transform hash values to string
            genesis.setSHA256(SHA256String);

            // signing the SHA256 hash with private key
            byte signedBytes[] = KeyTools.signData(SHA256String.getBytes(), Blockchain.keyPair.getPrivate());
            String SignedSHA256String = Base64.getEncoder().encodeToString(signedBytes);
            genesis.setSignedSHA256(SignedSHA256String);
        } catch (Exception e) {
            System.out.println("Error creating the dummy block");
        }
        return genesis;
    }

    public static boolean startServer(){
        /**
         * looping through public keys to make sure all 3 keys are fill on a local level from multicasting
         * server will only start if all keys are filled,
         * this ensures all processes are starting around the same time
         */
        for (PublicKey pk: publicKeys){
            if (pk == null){
                System.out.println("waiting for all public keys");
                return false;
            }
        }
        return true;
    }
    public static void main(String args[]) throws Exception{
        PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]); // parses argument for process ID
        file = "BlockInput" + PID + ".txt";     //hard coding file name

        System.out.println("Justin Zhang's Blockchain Project\n");
        System.out.println("Using Process ID " + PID + "\n");
        try {   //generating a public/private key pair
            Random  random = new Random();
            int randomInt = random.nextInt(1000);   //using a random seed to generate key
            keyPair = KeyTools.generateKeyPair(randomInt);
            publicKeys[PID] = keyPair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
        }


        BlockRecord genesis = createGenesis();  //creating genesis block

        //doing work as we would normally for an actual block
        String[] result = BlockUtility.doWork(genesis.getData(), genesis);
        byte signedHashBytes[] = KeyTools.signData(result[0].getBytes(), Blockchain.keyPair.getPrivate());
        String signedHash = Base64.getEncoder().encodeToString(signedHashBytes);


        genesis.setWinningHash(result[0]);  //the hash that solved the puzzle
        genesis.setRandomSeed(result[1]);   //the random seed used to solve the puzzle
        genesis.setSignedWinningHash(signedHash);   //signed winning hash
        blockchain.add(genesis);

        //we use a concurrent priority queue ordered by timestamp then blockID
        final BlockingQueue<BlockRecord> queue = new PriorityBlockingQueue<>();
        new Ports().setPorts(); //creating the port class that establishes the correct ports

        new Thread(new PublicKeyServer()).start(); // creating a new thread for key server and starting it
        new Thread(new UnverifiedBlockServer(queue)).start(); //creating a new thread for unverified block server
        new Thread(new BlockchainServer()).start(); //creating a new thread for verified block server

        try{Thread.sleep(1000);}catch(Exception e){} //sleep and wait for servers to start up

        /**
         * once process 2 joins it should go pass this while loop and start multi casting to other processes
         * once the other processes receive public key for process 2, it will also bypass this while loop
         */
        while (publicKeys[2] == null){
            System.out.println("Waiting for all processes to join");
            try{
                Thread.sleep(1500);
            } catch (Exception e) {e.printStackTrace();}
        }
        new Blockchain().MultiSend(true, false); // multicast key to other processes

        boolean start = false;

        //will only "start" if all processes received all public keys, ensure fairness
        while (start){
            start = startServer();
        }

        new Blockchain().MultiSend(false, true); //multicast unverified blocks to all process

        try{Thread.sleep(2000);}catch(Exception e){} //sleep and wait for all unverified blocks to settle in

        new Thread(new UnverifiedBlockConsumer(queue)).start(); //all process start consuming from queue, verify blocks


        /**
         * this section is the additional functionalities for the blockchain
         */
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String i;


        do {
            i = in.readLine();
            if (i.equals("L")) {    //list all blocks in the blockchain
                for (BlockRecord br: Blockchain.blockchain){
                    long bn = br.getBlockNumber();
                    String ts = br.getTimeStamp();
                    String fName = br.getFname();
                    String lName = br.getLname();
                    String dx = br.getDiag();
                    System.out.println(bn + " " + " " + ts + " " + fName + " " + lName + " " + dx);
                }
                consoleOptions();   //print out header once done
            }

            else if (i.equals("C")){    //displays how many blocks each process has verified
                int pZero = 0;
                int pOne = 0;
                int pTwo = 0;
                for (BlockRecord br: Blockchain.blockchain){
                    if (br.getVerificationProcessID() == 0){
                        pZero += 1;
                    }
                    else if (br.getVerificationProcessID() == 1){
                        pOne += 1;
                    }
                    else if (br.getVerificationProcessID() == 2){
                        pTwo += 1;
                    }
                }
                System.out.println("Process 0 verified " + pZero + " blocks.");
                System.out.println("Process 1 verified " + pOne + " blocks.");
                System.out.println("Process 2 verified " + pTwo + " blocks.");
                consoleOptions();   //print out header once done
            }

            else if (i.contains("R")){  //reads in a new .txt file and multicast BlockRecord to all processes
                String[] splits = i.split("\\s");
                file = splits[1];
                new Blockchain().MultiSend(false, true); // Multicast some new unverified blocks out to all servers as data
            }

        } while (true);
    }
}

class PublicKeyWorker extends Thread {
    Socket sock;    //declare socket object
    PublicKeyWorker (Socket s) {sock = s;} // constructor, instantiating socket
    public void run(){
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            int PID = Integer.parseInt(in.readLine());  //reading in process ID, used to index into local pk array
            String key = in.readLine ();    //reading in public key in string form
            PublicKey restoredKey;
            try {   //restoring public key
                byte[] bytePublicKey = Base64.getDecoder().decode(key);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytePublicKey);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                restoredKey = keyFactory.generatePublic(keySpec);
                Blockchain.publicKeys[PID] = restoredKey;

            } catch(Exception e) {
                e.printStackTrace();
            }
            sock.close();
        } catch (IOException x){x.printStackTrace();}
    }
}

class PublicKeyServer implements Runnable {
    /**
     * public key server, receives public key from other processes and stores into local public key array
     */
    public void run(){
        int q_len = 6;
        Socket sock;
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new PublicKeyWorker (sock).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

class UnverifiedBlockServer implements Runnable {
    /**
     * Unverified block server, receives unverified blocks multicasted from other processes
     * uses concurrent priority queue
     */
    BlockingQueue<BlockRecord> queue;
    UnverifiedBlockServer(BlockingQueue<BlockRecord> queue){
        this.queue = queue; // concurrent priority queue, when updated also updates the one in main method
    }

    class UnverifiedBlockWorker extends Thread { //
        Socket sock;    //declare socket object
        UnverifiedBlockWorker (Socket s) {sock = s;} //constructor, instantiating socket object
        public void run(){  //override method in Thread class
            try{
                BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

                Gson gson = new GsonBuilder().setPrettyPrinting().create();

                String numBlockString = in.readLine();

                int numBlock = Integer.parseInt(numBlockString);    //so we know how many blocks are coming

                for (int i = 0; i < numBlock; i++) {    //turning marshalled json string back into BlockRecord class
                    String block = in.readLine();
                    BlockRecord br = gson.fromJson(block, BlockRecord.class); //marshall back to BlockRecord
                    queue.put(br);
                }
                sock.close();
                System.out.println(numBlockString + " blocks have been added to unverified priority queue.");
            } catch (Exception x){x.printStackTrace();}
        }
    }

    public void run(){
        int q_len = 6; //max queue number
        Socket sock;
        System.out.println("Starting the Unverified Block Server input thread using " +
                Integer.toString(Ports.UnverifiedBlockServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {  //constantly listening for new requestss
                sock = servsock.accept(); //once it receives unverified block
                new UnverifiedBlockWorker(sock).start(); // starting the thread to process the unverified blocks
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

class BlockchainWorker extends Thread { //worker class for blockchain server
    Socket sock;    //declare socket object
    BlockchainWorker (Socket s) {sock = s;} //constructor that instantiates socket object
    public void run(){
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

            String data = in.readLine();    //reading in blockrecord
            Gson gson = new GsonBuilder().setPrettyPrinting().create(); //create gson object that formats json nicely
            BlockRecord br = gson.fromJson(data, BlockRecord.class);    //turning blockrecord from json to BlockRecord

            Blockchain.blockchain.add(br); // add this to local blockchain
            if (Blockchain.PID == 0){   //only process 0 writes updated blockchain to ledger
                try (FileWriter writer = new FileWriter("BlockchainLedger.json")) {
                    gson.toJson(Blockchain.blockchain, writer);
                } catch (IOException e) {e.printStackTrace();}
            }

            System.out.println("         --NEW BLOCKCHAIN--\n");
            for (BlockRecord b: Blockchain.blockchain){
                long bn = b.getBlockNumber();
                String ts = b.getTimeStamp();
                String fName = b.getFname();
                String lName = b.getLname();
                String dx = b.getDiag();
                System.out.println(bn + " " + " " + ts + " " + fName + " " + lName + " " + dx);
            }
            /*
            for (int i = 0; i < Blockchain.blockchain.size(); i++){
                System.out.println(Blockchain.blockchain.get(i).getFname());
            }

             */
            System.out.println("\n\n");
            sock.close();
        } catch (IOException x){x.printStackTrace();}
    }
}

class BlockchainServer implements Runnable {
    public void run(){
        int q_len = 6; /* Number of requests for OpSys to queue */
        Socket sock;
        System.out.println("Starting the blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
            while (true) {
                sock = servsock.accept();   //waiting for new verified blockrecord to arrive
                new BlockchainWorker (sock).start();    //once receives verified block record, start worker thread
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

class UnverifiedBlockConsumer implements Runnable {
    BlockingQueue<BlockRecord> queue;   //concurrent priority queue across main method and unverified block server
    UnverifiedBlockConsumer(BlockingQueue<BlockRecord> queue){
        this.queue = queue; // constructor that binds our priority queue, this is a concurrent priority queue
    }

    public void SendVerifiedBlock(BlockRecord br) {
        /**
         * method for sending verified block to all processes' blockchainserver
         */
        PrintStream toServer;   //declare printstream object
        Socket sock;            //declare socket object
        try{
            for(int i=0; i< Blockchain.numProcesses; i++){// Send a sample unverified block A to each server
                sock = new Socket(Blockchain.serverName, Ports.BlockchainServerPortBase + i);
                toServer = new PrintStream(sock.getOutputStream());

                //turning BlockRecord object into json string to marshall over network
                Gson gson = new Gson();
                String json = gson.toJson(br);

                toServer.println(json);
                toServer.flush();

                sock.close();
            }
        } catch (Exception x) {
        x.printStackTrace ();
        }
    }

    public void run(){
        BlockRecord data;

        System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
        try{
            while(true){ //constantly checking priority queue for unverified blocks
                data = queue.take(); // take vs. poll, take will block and wait for new records when queue is empty

                String json = BlockUtility.toJSON(data);    //marshall object to json string

                System.out.println("Consumer got unverified block: " + json);


                boolean blockExist = false;

                //checking if block id is in current blockchain, proceed if it is not
                for (BlockRecord br : Blockchain.blockchain)
                {
                    if (br.getBlockID().compareToIgnoreCase(data.getBlockID()) == 0)
                    {
                        blockExist = true;
                        break;
                    }
                }

                if (!blockExist){   //if block does not exist, do additional verification
                    //returning a boolean to see if blockID is verified or not
                    boolean verifiedBlockID = KeyTools.verifySig(
                            data.getBlockID().getBytes(),
                            Blockchain.publicKeys[Integer.parseInt(data.getCreatorProcessID())],
                            Base64.getDecoder().decode(data.getSignedBlockID())
                    );

                    if (verifiedBlockID){   //if blockID is verified then proceed
                        System.out.println("verified blockID");

                        //additional verification for SHA256, return boolean to see if it's verified or not
                        boolean verifiedSHA256 = KeyTools.verifySig(
                                data.getSHA256().getBytes(),
                                Blockchain.publicKeys[Integer.parseInt(data.getCreatorProcessID())],
                                Base64.getDecoder().decode(data.getSignedSHA256())
                        );
                        if (verifiedSHA256){    //proceed if SHA256 is verified
                            System.out.println("verified SHA256");

                            //setting the correct block number for current block
                            BlockRecord previousBlock = Blockchain.blockchain.get(Blockchain.blockchain.size()-1);
                            long previousBlockNumber = previousBlock.getBlockNumber();
                            long blockNumber = previousBlockNumber+1;

                            data.setBlockNumber(blockNumber);
                            data.setVerificationProcessID(Blockchain.PID);
                            System.out.println("Current BlockNumber: " + blockNumber);
                            System.out.println("Prevous BlockNumber: " + previousBlockNumber);

                            //concatenating data and previous winning hash together to do work on
                            String UB = previousBlock.getWinningHash()+ data.getData();
                            //do work on the UB yielding the winning hash and the random seed used to solve the puzzle
                            String[] result = BlockUtility.doWork(UB, data);

                            //signing the winnning hash
                            byte signedHashBytes[] = KeyTools.signData(result[0].getBytes(), Blockchain.keyPair.getPrivate());
                            String signedHash = Base64.getEncoder().encodeToString(signedHashBytes);

                            data.setWinningHash(result[0]);
                            data.setRandomSeed(result[1]);
                            data.setSignedWinningHash(signedHash);

                            System.out.println("Puzzle solved\n");

                            /**
                             * checking the ledger again to see if the block has been solved while work is being done
                             */
                            blockExist = false;
                            for (BlockRecord br : Blockchain.blockchain) {
                                if (br.getBlockID().compareToIgnoreCase(data.getBlockID()) == 0)
                                {
                                    blockExist = true;
                                    break;
                                }
                            }

                            if (!blockExist){
                                //if block doesn't exist, we multicast the new block to all processes
                                //including the verifying process itself
                                SendVerifiedBlock(data);
                                /**
                                 * we wait for a bit here, gives the block time to settle in
                                 * if we don't wait, this process will move onto the next unverified block interrupted
                                 * then the other processes will be behind.
                                 * unfair, since the puzzle doesn't take long to solve
                                 */

                                Thread.sleep(1500);
                                if (queue.isEmpty()){
                                    Blockchain.consoleOptions();
                                }

                            }
                            else {  //if the block exist, don't multicast to other process
                                System.out.println("Block exists, did all the work for nothing :(\n");
                            }

                        }
                    }
                }
                else{
                    System.out.println("Block exists\n");
                    if (queue.isEmpty()){
                        Blockchain.consoleOptions();
                    }
                }
            }
        }catch (Exception e) {System.out.println(e);}
    }
}

class KeyTools {
    /**
     * tool used to verify signature
     * returns a boolean variable
     * @param data
     * @param key
     * @param sig
     * @return
     * @throws Exception
     */
    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);

        return (signer.verify(sig));
    }

    /**
     * this method generate a KeyPair object
     * yield public and private key for a process
     * @param seed
     * @return
     * @throws Exception
     */
    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);

        return (keyGenerator.generateKeyPair());
    }

    /**
     * this method signs given byte data with private key generate by generateKeyPair method
     * can be verified with public of the same process
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }
}

class Ports {
    /**
     * setting the correct port number for each process
     * we set the base port number and increment it by process ID
     */
    final static int KeyServerPortBase = 4710;
    final static int UnverifiedBlockServerPortBase = 4820;
    final static int BlockchainServerPortBase = 4930;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    public void setPorts(){
        KeyServerPort = KeyServerPortBase + Blockchain.PID;
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + Blockchain.PID;
        BlockchainServerPort = BlockchainServerPortBase + Blockchain.PID;
    }
}

class BlockUtility {
    /**
     * a bunch of methods and tools to manipulate block
     */
    String fileName;
    //the string used to generate random seed
    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    BlockUtility(String fileName){      //constructor which instantiates fileName
        this.fileName = fileName;
    }

    /**
     * a method that yields an ArrayList of BlockRecord
     * use the fileName indicated from constructor
     * @return
     */
    public ArrayList<BlockRecord> create(){
        ArrayList<BlockRecord> blockRecords = new ArrayList<>();

        try{
            String line;
            BufferedReader br = new BufferedReader(new FileReader(fileName));
            while ((line = br.readLine()) != null){
                String[] splits = line.split("\\s+");   //splitting the line by spaces
                BlockRecord blockRecord = new BlockRecord();    //creating new BlockRecord object for each new block

                //most of these are the same as creating genesis block
                String blockID = new String(UUID.randomUUID().toString());
                blockRecord.setBlockID(blockID);
                byte signedBlockIDbytes[] = KeyTools.signData(blockID.getBytes(), Blockchain.keyPair.getPrivate());
                String signedBlockID = Base64.getEncoder().encodeToString(signedBlockIDbytes);
                blockRecord.setSignedBlockID(signedBlockID);
                blockRecord.setCreatorProcessID(String.valueOf(Blockchain.PID));
                blockRecord.setUUID(UUID.randomUUID());
                Date date = new Date();
                String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                String TimeStampString = T1 + "." + Blockchain.PID;
                blockRecord.setTimeStamp(TimeStampString);
                blockRecord.setFname(splits[0]);
                blockRecord.setLname(splits[1]);
                blockRecord.setDOB(splits[2]);
                blockRecord.setSSNum(splits[3]);
                blockRecord.setDiag(splits[4]);
                blockRecord.setTreat(splits[5]);
                blockRecord.setRx(splits[6]);
                blockRecord.setData(line);

                //creating SHA256 hash from raw data
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                messageDigest.update(line.getBytes());
                byte bytes[] = messageDigest.digest();
                StringBuffer sb = new StringBuffer();
                for (int i = 0; i < bytes.length; i++) {
                    sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
                }
                String SHA256String = sb.toString();
                blockRecord.setSHA256(SHA256String);

                // sign the SHA256 hash with private key
                byte signedBytes[] = KeyTools.signData(SHA256String.getBytes(), Blockchain.keyPair.getPrivate());
                String SignedSHA256String = Base64.getEncoder().encodeToString(signedBytes);
                blockRecord.setSignedSHA256(SignedSHA256String);

                blockRecords.add(blockRecord);
            }
            br.close();
        }catch (Exception e) {
            System.out.println(e);
        }
        return blockRecords;

    }

    /**
     * this is where we do work, solve the puzzle
     * returns the hash and random seed that solved the puzzle
     * we calculate the first 16 bits of hash as work number
     * work number has to be under 10000 in order to solve the puzzle
     * @param data
     * @param blockRecord
     * @return
     */
    public static String[] doWork(String data, BlockRecord blockRecord) {
        String[] answer = new String[2];    //the two things returned when puzzle is solved

        String randSeed = randomAlphaNumeric(8);    //creating a random alphanumeric string that's 8 char long
        String hash = "";
        System.out.println("Our example random seed string is: " + randSeed + "\n");


        System.out.println("Number will be between 0 and 65535\n");
        int workNumber = 0;

        try {
            boolean flag = true;    //setting a flag that turns false when puzzle is solved
            while (flag){
                randSeed = randomAlphaNumeric(8); // getting a random alphanumeric string

                //concatenating the random string with data and previous winnning hash
                String concatString = data + randSeed;

                //turning this concatenated string into a SHA256 hash
                MessageDigest MD = MessageDigest.getInstance("SHA-256");
                byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8")); // Get the hash value
                StringBuilder hex = new StringBuilder(bytesHash.length * 2);
                for(int k=0; k < bytesHash.length; k++){
                    hex.append(String.format("%02X", bytesHash[k]));
                }
                hash = hex.toString();  //to string method
                System.out.println("Hash is: " + hash);

                //parse hash's first 4 characters into integer.
                workNumber = Integer.parseInt(hash.substring(0,4),16);
                System.out.println("First 16 bits in decimal: " + workNumber);

                if (!(workNumber < 10000)){  // lower number = more work.
                    System.out.format("%d is not less than 10,000 so we did not solve the puzzle\n\n", workNumber);
                }
                if (workNumber < 10000){
                    System.out.format("%d IS less than 10,000 so puzzle solved!\n", workNumber);
                    System.out.println("The seed (puzzle answer) was: " + randSeed);
                    flag = false;       //switch flag to terminate while loop
                }

                //always check for the tail of current blockchain after each cycle of work
                //make sure we don't do work on a solved puzzle
                if (blockRecord.getBlockNumber() != 0){
                    BlockRecord recentBlock = Blockchain.blockchain.get(Blockchain.blockchain.size()-1);
                    if (blockRecord.getBlockID().compareToIgnoreCase(recentBlock.getBlockID()) == 0){
                        System.out.println("did work for nothing");
                        break;
                    }
                }
            }
        }catch(Exception ex) {ex.printStackTrace();}
        answer[0] = hash;
        answer[1] = randSeed;
        return answer;
    }

    /**
     * method that generates a random alphanumeric string for our work method
     * @param count
     * @return
     */
    public static String randomAlphaNumeric(int count) {
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int) (Math.random() * ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }


    /**
     * turns BlockRecord into string json format
     * @param br
     * @return
     */
    public static String toJSON(BlockRecord br){
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(br);
        return json;
    }
}

class BlockRecord implements Comparable<BlockRecord>{
    /**
     * attributes describing the block, self explanatory names
     */
    String data;
    long blockNumber;
    String SHA256;
    String signedSHA256;
    String BlockID;
    String TimeStamp;
    String creatorProcessID;
    int VerificationProcessID;
    String PreviousHash;
    UUID uuid;
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String RandomSeed;
    String WinningHash;
    String signedWinningHash;
    String Diag;
    String Treat;
    String Rx;
    String signedBlockID;

    /**
     *accessor and setters for block record fields
     */
    public String getData(){ return data;}
    public void setData(String data) {this.data = data;}

    public long getBlockNumber(){ return blockNumber;}
    public void setBlockNumber(long blockNumber) {this.blockNumber = blockNumber;}

    public String getSHA256(){return SHA256;}
    public void setSHA256(String SHA256){this.SHA256 = SHA256;}

    public String getSignedSHA256(){return signedSHA256;}
    public void setSignedSHA256(String signedSHA256){this.signedSHA256 = signedSHA256;}

    public String getBlockID() {return BlockID;}
    public void setBlockID(String BID){this.BlockID = BID;}

    public String getTimeStamp() {return TimeStamp;}
    public void setTimeStamp(String TS){this.TimeStamp = TS;}

    public String getCreatorProcessID() {return creatorProcessID;}
    public void setCreatorProcessID(String creatorProcessID){this.creatorProcessID = creatorProcessID;}

    public int getVerificationProcessID() {return VerificationProcessID;}
    public void setVerificationProcessID(int verificationProcessID){this.VerificationProcessID = verificationProcessID;}

    public String getPreviousHash() {return this.PreviousHash;}
    public void setPreviousHash (String PH){this.PreviousHash = PH;}

    public UUID getUUID() {return uuid;}
    public void setUUID (UUID ud){this.uuid = ud;}

    public String getLname() {return Lname;}
    public void setLname (String LN){this.Lname = LN;}

    public String getFname() {return Fname;}
    public void setFname (String FN){this.Fname = FN;}

    public String getSSNum() {return SSNum;}
    public void setSSNum (String SS){this.SSNum = SS;}

    public String getDOB() {return DOB;}
    public void setDOB (String RS){this.DOB = RS;}

    public String getRandomSeed() {return RandomSeed;}
    public void setRandomSeed (String RS){this.RandomSeed = RS;}

    public String getWinningHash() {return WinningHash;}
    public void setWinningHash (String WH){this.WinningHash = WH;}

    public String getSignedWinningHash() {return signedWinningHash;}
    public void setSignedWinningHash (String SWH){this.signedWinningHash = SWH;}

    public String getDiag() {return Diag;}
    public void setDiag (String D){this.Diag = D;}

    public String getTreat() {return Treat;}
    public void setTreat (String Tr){this.Treat = Tr;}

    public String getRx() {return Rx;}
    public void setRx (String Rx){this.Rx = Rx;}

    public String getSignedBlockID() {return signedBlockID;}
    public void setSignedBlockID(String signedBlockID) { this.signedBlockID = signedBlockID;}


    //implemented compareTo to order priority queue by timestamp then blockID
    @Override
    public int compareTo(BlockRecord blockRecord) {
        if (this.getTimeStamp().compareTo(blockRecord.getTimeStamp()) == 0){
            return this.getBlockID().compareTo(blockRecord.getBlockID());
        }
        else {
            return this.getTimeStamp().compareTo(blockRecord.getTimeStamp());
        }

    }
}