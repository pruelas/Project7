
import java.io.*;
import java.net.Socket;
import java.net.ServerSocket;
import java.util.Scanner;
import java.security.*;
import java.util.zip.CRC32;
import javax.crypto.*;

public final class FileTransfer{

  public static void main(String[] args) throws Exception {
      
    if(args[0].equals("makekeys")){
      //When first command line argument is makekeys
      try {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");

        gen.initialize(4096); // you can use 2048 for faster key generation

        KeyPair keyPair = gen.genKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        try (ObjectOutputStream oos = new ObjectOutputStream(
               new FileOutputStream(new File("public.bin")))) {

          oos.writeObject(publicKey);
        }

        try (ObjectOutputStream oos = new ObjectOutputStream(
               new FileOutputStream(new File("private.bin")))) {

          oos.writeObject(privateKey);
        }

      }catch (NoSuchAlgorithmException | IOException e) {
          e.printStackTrace(System.err);
      }

    //When program is acting as the Server.
    //Arg 1 is server
    //Arg 2 is name of file with private key
    //Arg 3 is the port number
    }else if(args[0].equals("server")){
        if(args.length != 3){
          System.out.println("Error with command line arguments.");

        }else{
          String fileName = args[1];
          int portNumber = Integer.valueOf(args[2]);

          //Open socket and listen for a connection
          try (ServerSocket serverSocket = new ServerSocket(portNumber)) {

            while (true) {

              System.out.println("\nWaiting for Client...");

              try (Socket socket = serverSocket.accept()) {
                System.out.println("Client connected");
                OutputStream os = socket.getOutputStream();
                ObjectOutputStream oOS = new ObjectOutputStream(os);

                InputStream is = socket.getInputStream();
                ObjectInputStream in = new ObjectInputStream(is);

                Key sessionKey = null;
                int seqNumber = 0; //used to keep track of next chunk expected
                      
                //Stored object sent by client
                Message mS = (Message)in.readObject(); 

                FileWriter outputStream = null;
                int size = 0;
                int totalChunks = 0;
                int fileSize = 0;
                int chunkSize = 0;

                //Loop that will contitnue running as long as the server is sending messages
                while(mS != null){
                    
                  if(mS.getType() == MessageType.DISCONNECT){
                    //Close current connection
                    break;

                  }else if(mS.getType() == MessageType.START){
                    StartMessage sM = (StartMessage) mS;

                    //Decrypt key passed by server using the servers public key
                    try{
                      FileInputStream fIS = new FileInputStream(fileName);
                      ObjectInputStream oIS = new ObjectInputStream(fIS);
                      PrivateKey serverPK= (PrivateKey) oIS.readObject();

                      //DEcrypt session key using server's public key
                      Cipher cipherK = Cipher.getInstance("RSA");
                      cipherK.init(Cipher.UNWRAP_MODE, serverPK);
                      sessionKey = (Key) cipherK.unwrap(sM.getEncryptedKey(), "AES", Cipher.SECRET_KEY);
                      
                      
                      }catch(Exception e){
                        seqNumber = -1;
                      }

                      //Open file where data will be written
                      outputStream = new FileWriter("test2.txt");
                      chunkSize = sM.getChunkSize();
                      fileSize = (int)sM.getSize();
                      totalChunks = (int) Math.ceil(((float)sM.getSize() / (float)sM.getChunkSize()));
                      size = totalChunks;
                      //Send Ackmessage to server indicationg whether or not the file transfer can occur
                      AckMessage aM = new AckMessage(seqNumber);
                      oOS.writeObject(aM);
                      

                    }else if(mS.getType() == MessageType.STOP){ 
                      //Discard associated file transfer
                      //Respond with AckMessage with sequence number -1
                      AckMessage ak = new AckMessage(-1);
                      oOS.writeObject(ak);
                      break;
                      
                    }else if(mS.getType() == MessageType.CHUNK){
                      Chunk cH = (Chunk)mS;
                      AckMessage ak;
                      System.out.println("Chunk received [" +(cH.getSeq()+1) +"/"+ (size) + "].");
                      
                      //If sequence number is the one expected
                      //Decrypt data in Chunk using initial session key
                      if(seqNumber == cH.getSeq() ){
                        Cipher cipher = Cipher.getInstance("AES");  
                        cipher.init(Cipher.DECRYPT_MODE, sessionKey);
                        byte[] data = cipher.doFinal(cH.getData());

                      
                        //Calculate CRC32 for decrypted data and compare it with CRC32 value in Chunk 
                        CRC32 cr = new CRC32();
                        cr.update(data);
                        int value = (int)cr.getValue();
                       
                        if(value == cH.getCrc()){
                          //Store chunk by storting data and incrementing seqNum

                          //Add data to test2.txt
                          if(seqNumber == (size-1) && (fileSize%chunkSize != 0)){
                            for(int i = 0; i<(fileSize%chunkSize); i++){
                              outputStream.write((char) data[i]);
                            }
                          }else{
                            for(int i = 0; i<chunkSize; i++){
                              outputStream.write((char) data[i]);
                            }
                          }
                          seqNumber++;
                          ak = new AckMessage(seqNumber);
                      }

                        ak = new AckMessage(seqNumber-1);
                      
                      }else{
                        ak = new AckMessage(seqNumber);
                      }
                      
                      //Send ack to client
                      oOS.writeObject(ak);

                      //Closes connection if all the chunks have been received
                      if(ak.getSeq()+1 == totalChunks){
                        System.out.println("Transfer complete."); 
                        System.out.println("Output path: test2.txt");
                        outputStream.close();
                        break;
                      }
                    }//if CHUNK
                    
                  //Read next message sent by client
                  mS = (Message)in.readObject();

                  }//WHile loop
               }//Try server socket
            }//while
          }//try server socket
        }//else 

    //When program is acting as the Client
    //Arg 1 is client
    //Arg 2 is file name with public key
    //Arg 3 is host
    //Arg 4 is port number
    }else if(args[0].equals("client")){
      if(args.length != 4){
        System.out.println("Error with command line arguments.");

      }else{
        String fileName = args[1];
        String host = args[2];
        int portNumber = Integer.valueOf(args[3]);

        try (Socket socket = new Socket(host, portNumber)) {
          
          String address = socket.getInetAddress().getHostAddress();
          System.out.println("Connected to server: " + host + "/" + address);
 
          //Generate AES session key
          KeyGenerator kG = KeyGenerator.getInstance("AES");
          Key serverPK = null;
          try{
            //Obtain public key
            FileInputStream fIS = new FileInputStream(fileName);
            ObjectInputStream oIS = new ObjectInputStream(fIS);
            serverPK= (Key) oIS.readObject();
              

          }catch(Exception e){
            System.out.println("error");
          }

          SecretKey sK = (SecretKey)kG.generateKey(); 

          //Encrypt session key using server's public key
          Cipher cipher = Cipher.getInstance("RSA");
          cipher.init(Cipher.WRAP_MODE, serverPK);
          byte[] wrappedKey = cipher.wrap(sK);

          //Prompt user for path
          Scanner sc = new Scanner(System.in);
          System.out.print("Enter path :");
          String path = sc.next();
          BufferedReader br = null;
          try{
            br = new BufferedReader(new FileReader(path));
          }catch(Exception e){
            System.out.println("Invalid path");
            System.exit(0);
          }  

          //If path is valid, ask user for desired chunk size
          System.out.print("Enter chunk size [1024]:");
          int b = sc.nextInt();

          //Send the serve a StartMessage with file name, length of file in bytes,
          //chunk size, and encrypted session key.
          StartMessage SM = new StartMessage(path, wrappedKey, b); 
          OutputStream os = socket.getOutputStream();
          ObjectOutputStream oOS = new ObjectOutputStream(os);

          oOS.writeObject(SM);

          int n = (int) Math.ceil(((float)SM.getSize() / (float)SM.getChunkSize()));

          //Receive AckMessage. See if number 0 or if -1
          InputStream is = socket.getInputStream();
          ObjectInputStream in = new ObjectInputStream(is); 
          AckMessage aC = (AckMessage) in.readObject();

          byte[] data = new byte[b];
          int counter = 0;
              
          if(aC.getSeq() == -1){
            System.out.println("Transfer can't proceed");
            System.exit(0);
          }else {
            System.out.println("Sending: " + path + ". " + "File size: " + SM.getSize() + ".");
            System.out.println("Sending " + n + " chunks.");    
            int i = 0;
            int c = 0;

            while(i < n){
              //Send each chunk of file in order. After each chunk, wait for ack mesage.
              //Number should be the number expected 

              //Read characters from file one by one and add to the data of the chunk
              while(counter < b && (c = br.read()) != -1 ){
                data[counter] = (byte) c;
                counter++;
              }

              //Initiate a CRC object to compute the CRC value for the data of the chunk
              CRC32 cr = new CRC32();
              cr.update(data);
              int value = (int)cr.getValue();

              //Encrypt data using a session key
              cipher = Cipher.getInstance("AES");
              cipher.init(Cipher.ENCRYPT_MODE, sK);
              data = cipher.doFinal(data);

              //Reset counter to 0. Ensures only a certain amount of data is added to the array data
              counter = 0;
             
              //Create new chunk and sent to server
              Chunk ch = new Chunk(i, data, value); 
              oOS.writeObject(ch);

              //Receive ack message from server
              AckMessage AM = (AckMessage) in.readObject();
              if(AM.getSeq() != (i))
                break;

              System.out.println("Chunks completed ["+ (i+1) +"/"+ n +"].");
              i++;
              }          
            }
          }//try
      }
    }else{
       System.out.println("Error with command line arguments.");
    }    
  }
  
}















