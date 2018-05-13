/**
 *
 * @author 
 */

package completechat;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket; 
import java.net.Socket; 
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

public class chatServer extends JFrame {

	private static boolean encryptionEnabled;
	private static boolean fileEncryptionEnabled;
	private JFileChooser fc;	
	private static JTextArea jtaResult;
	private static JTextArea msg_area;
	private static JTextField serverAttachDisplay;
	private static JTextField msg_text;

	private JButton msg_send;
	private JButton recieveAttach;
	private JButton sendAttach;
	private JButton serverAttach;

	private JButton Decrypt;
	private JToggleButton Encrypt;
	private JButton encryptRSA;
	private JButton decryptRSA;
	private JButton receiveFileAES;
	private JToggleButton EncryptFiles;

	static ServerSocket ss;
	static Socket s; // client socket. (s = socket).

	static ServerSocket ss2; //server socket.
	static Socket s2; // client socket.

	static ServerSocket ss3; // server AES Socket (string)
	static Socket s3;  // client AES Socket (string)

	static ServerSocket ss4; // server AES Socket (File Transfer)
	static Socket s4; // client AES Socket (File Transfer)

	static ServerSocket ss5; // server RSA Socket (message)
	static Socket s5; // client RSA Socket (message)

	static DataInputStream din; // din = data input
	static DataOutputStream dout; // dout = data output

	static DataInputStream din2; // din2 = data input for file transfer
	static DataOutputStream dout2; // dout2 = data output for file transfer
	static File f; // Create f of type File. Needed for pathnames.

	static DataInputStream din3; // din3 = data input for AES  (String)
	static DataOutputStream dout3; // dout3 = data output for AES (String)

	static DataInputStream din4; // din4 = data input for AES (File transfer)
	static DataOutputStream dout4; // dout4 = data output for AES (File transfer)

	static DataInputStream din5; // din5 = data input for RSA (message)
	static DataOutputStream dout5; // dout5 = data output for RSA (message)

	static AESAlgorithm aesAlgo; // For AES
	static RSAAlgorithm rsaObj = new RSAAlgorithm(); // for RSA

	static BigInteger privateModulus; // hold teh modulus of the private key
	static BigInteger privateExponent; // hold the exponent of the private key
	static BigInteger publicModulus; // hold the modulus of the public key
	static BigInteger publicExponent; // hold the exponent of the public key

	static BigInteger clientPrivateModulus; // hold the client's private modulus for private key
	static BigInteger clientPrivateExponent; // hold the client's private exponent for private key

	static PublicKey publicKey; // hold the Server's public key
	static PrivateKey privateKey; // hold the Server's private key

	static PublicKey encryptKey; // hold the Client's public key

	private String passA = "ServerPassKey"; // The Server's part of the Session Key
	private String passB; // The client's part of the Session key
	private String passwordComplete; // This is the complete Session Key
	private byte[] sessionKey; // the mutually generated session key 
	private byte[] sessionPassword; // the hashed session as 16 bytes

	public chatServer() {
		this.setDefaultCloseOperation(EXIT_ON_CLOSE);
		this.setMinimumSize(new Dimension(640,480));

		this.setLayout(new GridBagLayout());
		GridBagConstraints gridLayout = new GridBagConstraints();

		msg_area = new JTextArea(5, 20);
		msg_text = new JTextField(25);
		fc = new JFileChooser();
		serverAttachDisplay = new JTextField();
		serverAttachDisplay.setEditable(false);
		jtaResult = new JTextArea(5, 20);


		sendAttach = new JButton( "Send File", new ImageIcon(chatServer.class.getResource("upload.png"))); 
		recieveAttach = new JButton("Save File", new ImageIcon(chatServer.class.getResource("download.png")));
		serverAttach = new JButton( "Attach File", new ImageIcon(chatServer.class.getResource("attach2.png")));
		msg_send = new JButton( "Send Text", new ImageIcon(chatServer.class.getResource("send.png")));

		Encrypt = new JToggleButton("AES Encrypt");
		Decrypt = new JButton("AES Decrypt");
		EncryptFiles = new JToggleButton("Encrypt File");
		receiveFileAES = new JButton("Decrypt File");
		encryptRSA = new JButton("RSA Encrypt");
		decryptRSA = new JButton("RSA Decrypt");

		setDefaultCloseOperation(EXIT_ON_CLOSE);
		setTitle("ChatBackground");
		setName("Server");
		setResizable(false);

		this.setTitle("Chat Server Window");
		this.setVisible(true);

		msg_area.setEditable(false);
		msg_area.setLineWrap(true);

		msg_send.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				msg_sendActionPerformed(evt);
			}
		});

		serverAttach.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				serverAttachActionPerformed(evt);
			}
		});

		sendAttach.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				sendAttachActionPerformed(evt);
			}
		});
		recieveAttach.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				recieveAttachActionPerformed(evt);
			}
		});

		jtaResult.setEditable(false);
		jtaResult.setBorder(BorderFactory.createTitledBorder("Encrypted/Decrypted Text"));

		JScrollPane scroll = new JScrollPane(msg_area);

		scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);
		
		Encrypt.addActionListener(new ActionListener() {
	         public void actionPerformed(ActionEvent e) {
	            JToggleButton tBtn = (JToggleButton)e.getSource();
	            if (tBtn.isSelected()) {
	               encryptionEnabled = true;
	               msg_area.setText(msg_area.getText().trim()+"\nServer:\t"+"[Encryption Started]");
					try {
						dout.writeUTF("[Encryption Started]");
					} catch (Exception err) {
						err.printStackTrace();
					}
	            } else {
	            	encryptionEnabled = false;
	            	msg_area.setText(msg_area.getText().trim()+"\nServer:\t"+"[Encryption Ended]");
					try {
						dout.writeUTF("[Encryption Ended]");
					} catch (Exception err) {
						err.printStackTrace();
					}
	            }
	         }
	      });


		EncryptFiles.addActionListener(new ActionListener() {
	         public void actionPerformed(ActionEvent e) {
	            JToggleButton tBtn1 = (JToggleButton)e.getSource();
	            if (tBtn1.isSelected()) {
	               fileEncryptionEnabled = true;
	               msg_area.setText(msg_area.getText().trim()+"\nServer:\t"+"[File Encryption Started]");
					try {
						dout.writeUTF("[File Encryption Started]");
					} catch (Exception err) {
						err.printStackTrace();
					}
	            } else {
	            	fileEncryptionEnabled = false;
	            	msg_area.setText(msg_area.getText().trim()+"\nServer:\t"+"[File Encryption Ended]");
					try {
						dout.writeUTF("[File Encryption Ended]");
					} catch (Exception err) {
						err.printStackTrace();
					}
	            }
	         }
	      });
		
		Decrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				DecryptActionPerformed(evt);
			}
		});

		encryptRSA.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				encryptRSAActionPerformed(evt);
			}
		});

		decryptRSA.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				receiveRSAActionPerformed(evt);
			}
		});
		
		gridLayout.gridx = 0;
		gridLayout.gridy = 0;
		gridLayout.weightx = 1;
		gridLayout.weighty = 1;
		gridLayout.gridwidth = 6;
		gridLayout.gridheight = 3;
		gridLayout.fill = GridBagConstraints.BOTH;
		gridLayout.insets = new Insets(5, 5, 5, 5);
		this.add(scroll, gridLayout);

		gridLayout.gridx = 0;
		gridLayout.gridy = 3;
		gridLayout.gridwidth = 6;
		gridLayout.gridheight = 2;
		this.add(jtaResult, gridLayout);

		gridLayout.gridx = 1;
		gridLayout.gridy = 5;
		gridLayout.weighty = 0.1;
		gridLayout.gridheight = 1;
		gridLayout.gridwidth = 1;
		this.add(Encrypt, gridLayout);

		gridLayout.gridx = 2;
		gridLayout.gridy = 5;
		gridLayout.weighty = 0.1;
		gridLayout.gridheight = 1;
		gridLayout.gridwidth = 1;
		this.add(Decrypt, gridLayout);

		gridLayout.gridx = 3;
		gridLayout.gridy = 5;
		gridLayout.gridheight = 1;
		gridLayout.gridwidth = 1;
		this.add(EncryptFiles, gridLayout);

//		gridLayout.gridx = 1;
//		gridLayout.gridy = 5;
//		gridLayout.gridheight = 1;
//		gridLayout.gridwidth = 1;
//		this.add(receiveFileAES, gridLayout);
//
//		gridLayout.gridx = 2;
//		gridLayout.gridy = 4;
//		gridLayout.gridheight = 1;
//		gridLayout.gridwidth = 1;
//		this.add(encryptRSA, gridLayout);
//
//		gridLayout.gridx = 2;
//		gridLayout.gridy = 5;
//		gridLayout.gridheight = 1;
//		gridLayout.gridwidth = 1;
//		this.add(decryptRSA, gridLayout);

		gridLayout.gridx = 0;
		gridLayout.gridy = 6;
		gridLayout.weighty = 0;
		gridLayout.gridwidth = 4;
		gridLayout.gridheight = 1;
		this.add(msg_text, gridLayout);


		gridLayout.gridx = 0;
		gridLayout.gridy = 7;
		gridLayout.weighty = 0;
		gridLayout.gridwidth = 4;
		gridLayout.gridheight = 1;
		this.add(serverAttachDisplay, gridLayout);

		gridLayout.gridx = 4;
		gridLayout.gridy = 6;
		gridLayout.weightx = 0;
		gridLayout.gridwidth = 1;
		this.add(msg_send, gridLayout);

		gridLayout.gridx = 5;
		gridLayout.gridy = 7;
		gridLayout.weightx = 0;
		gridLayout.gridwidth = 1;
		this.add(sendAttach, gridLayout);

		gridLayout.gridx = 4;
		gridLayout.gridy = 7;
		gridLayout.weightx = 0;
		gridLayout.gridwidth = 1;
		this.add(serverAttach, gridLayout);

		gridLayout.gridx = 5;
		gridLayout.gridy = 6;
		gridLayout.weightx = 0;
		gridLayout.gridwidth = 1;
		this.add(recieveAttach, gridLayout);

		// Here we passed key to constructor
		//aesAlgo = new AESAlgorithm(keyValue); 
		
		try
		{
			rsaObj.generateKeys(); // generate keys for RSA
			privateModulus = rsaObj.getPrivateModulus(); // get the private modulus of the object
			privateExponent = rsaObj.getPrivateExponent(); // get the private exponent of the object
			publicModulus = rsaObj.getPublicModulus(); // get the public modulus of the object
			publicExponent = rsaObj.getPublicExponent(); // get the public exponent of the object
			publicKey = rsaObj.getPubKey(publicModulus, publicExponent); //get public key to send to client
		} // end try
		catch(Exception e)
		{
			e.printStackTrace();
		} // end catch
	}

	public Key generateKey() throws NoSuchAlgorithmException // code to generate key for AES
	{
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		SecureRandom random = new SecureRandom();
		kg.init(random);
		return kg.generateKey();
	}

	private void msg_sendActionPerformed(ActionEvent evt) { // Method for Send button
		if(encryptionEnabled == false) {
			try{
				String msgout = "";
				msgout= msg_text.getText().trim();
				msg_area.setText(msg_area.getText().trim()+"\nServer:\t"+msgout); // print msg
				dout.writeUTF(msgout); // sending the server message to the client
				msg_text.setText("");
			}
			catch(Exception e){
				e.printStackTrace();
			}
		} else {
			EncryptActionPerformed();
		}
	}

	private void serverAttachActionPerformed(ActionEvent evt) // Attach Button Method
	{
		JFileChooser chooser = new JFileChooser(); // create object of JFileChooser
		chooser.showOpenDialog(null); // choose file
		f = chooser.getSelectedFile(); // assign the file equal to f
		String filename = f.getAbsolutePath(); // filename = the path of f.
		serverAttachDisplay.setText(filename); // display directory of f in attach window   
	}

	private void sendAttachActionPerformed(ActionEvent evt) { // Send Attachment Button    
		// Transfer file after the user has selected a file to attach
		
		if(fileEncryptionEnabled == false) {
			try{
				int fileSize = (int) f.length(); // gets the file size
				byte[] myByteArray = new byte[(int) f.length()]; 
				dout2.writeInt(fileSize); // writes to outputstream
				BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f));
				bis.read(myByteArray, 0, myByteArray.length);
				OutputStream os = s2.getOutputStream();
				os.write(myByteArray, 0, myByteArray.length);
				os.flush(); // forces any buffered output bytes to be written out.
			}
			catch(Exception e){
				e.printStackTrace();
			}
		}else {
			transferFileAESActionPerformed();
		}
		String temp = msg_area.getText().trim()+"\nServer:\t"+"[Sending File]";
		SwingUtilities.invokeLater(new Runnable() {
			// except this is queued onto the event thread.
			public void run() {
				msg_area.setText(temp);
			}
		});
		try {
			dout.writeUTF("[Sending File]");
		} catch (Exception err) {
			err.printStackTrace();
		}
	}

	private void recieveAttachActionPerformed(ActionEvent evt) { //method to Receive Attachment
		if(fileEncryptionEnabled == false) {		
			try{
				if(din2.available()==0) {
					return;
				} // end if
				JFileChooser chooser = new JFileChooser(); 
				chooser.showSaveDialog(null); // choose save location
				f = chooser.getSelectedFile(); // assign the file equal to f
				int fileSize = din2.readInt();
				byte[] myByteArray = new byte[fileSize];
				InputStream is = s2.getInputStream();
				din2.readFully(myByteArray);// Reads bytes from the input stream din2
				FileOutputStream fos = new FileOutputStream(f); //write to the file specified by f
				fos.write(myByteArray);
				fos.close(); // Closes file output stream
			}
			catch(Exception e){
				e.printStackTrace(); 
			} 
		} else {
				receiveFileAESActionPerformed();
		}
		String temp = msg_area.getText().trim()+"\nServer:\t"+"[File Received]";
		SwingUtilities.invokeLater(new Runnable() {
			// except this is queued onto the event thread.
			public void run() {
				msg_area.setText(temp);
			}
		});
		try {
			dout.writeUTF("[File Sent]");
		} catch (Exception err) {
			err.printStackTrace();
		}
	}

	private void EncryptActionPerformed() { // Encrypts the Data in AES 
		try
		{
			System.out.println("Requesting Client's RSA Public"); //Get RSA Public Key
			ObjectInputStream ois = new ObjectInputStream(s4.getInputStream()); // Receive RSA Public
			encryptKey = (PublicKey) ois.readObject(); // recieve clients Public Key
			System.out.println("Client's RSA Public key received.");

			System.out.println("Sending RSA Public Key to Client");
			ObjectOutputStream oos = new ObjectOutputStream(s5.getOutputStream());
			oos.writeObject(publicKey); //Send server's Public Key
			oos.flush();
			System.out.println("Server's RSA Public Key Sent"); 

			//STEP 1: Hash the Pass A, Digitaly Sign with private key and Encrypt with RSA public key
			privateKey = rsaObj.getPrivateKey(privateModulus, privateExponent);
			byte[] passAData = passA.getBytes();
			Signature sig = Signature.getInstance("SHA1WithRSA"); // hashing algorithm to use.
			sig.initSign(privateKey); 
			sig.update(passAData);
			byte[] signatureBytes = sig.sign();  // signing and hashing of Pass A. [integrity + ds}

			byte[] encryptedChallenge = rsaObj.publicKeyEncrypt(passAData, encryptKey); 
			ObjectOutputStream oos1 = new ObjectOutputStream(s4.getOutputStream()); 
			oos1.writeObject(encryptedChallenge); // Send Challenge over the socket to Client
			ObjectOutputStream oos2 = new ObjectOutputStream(s5.getOutputStream());//set up a new output stream
			System.out.println("Sending the Encrypted Digitally Signed Hashed PassA to Client.");
			oos2.writeObject(signatureBytes); // Send Encrypted Digitally Signed Hashed PassA over the socket to Client
			System.out.println("Step 1 Completed.");

			//STEP 4: Decipher data sent from Client and save session key
			ObjectInputStream ois1a = new ObjectInputStream(s3.getInputStream());
			ObjectInputStream ois2a = new ObjectInputStream(s5.getInputStream());
			ObjectInputStream ois3a = new ObjectInputStream(s4.getInputStream());

			String clientsChallenge = null;
			String clientsResponse = null;
			byte[] decryptedChal = null;
			byte[] decryptedResp = null;
			byte[] decryptedIntPassBr = null;
			byte[] decryptedIntPassAr = null;
			int challengeChecker = 0; // used to see if challenge is valid
			while(challengeChecker == 0)
			{
				System.out.println("Verifying Challenge and Creating Session Key.");
				byte[] clientChallenge = (byte[]) ois1a.readObject(); // read in challenge
				decryptedChal = rsaObj.privateKeyDecrypt(clientChallenge, privateModulus, privateExponent); // decrypt challenge
				clientsChallenge = new String (decryptedChal);
				passwordComplete = passA + clientsChallenge; 
				System.out.println("Session Key is: " + passwordComplete);
				MessageDigest hash = MessageDigest.getInstance("SHA-1");
				hash.reset();
				hash.update(passwordComplete.getBytes()); // prepare to hash
				sessionKey = hash.digest(); // hash the session key
				MessageDigest bringSios = MessageDigest.getInstance("MD5");
				bringSios.reset(); 
				bringSios.update(sessionKey);
				sessionPassword = bringSios.digest(); 
				aesAlgo = new AESAlgorithm(sessionPassword); 
				
				byte[] clientResponse = (byte[]) ois2a.readObject(); // read in Response
				decryptedResp = rsaObj.privateKeyDecrypt(clientResponse, privateModulus, privateExponent); // decrypt response with rsa
				clientsResponse = new String (decryptedResp);
				String decryptedPassA = aesAlgo.decrypt(clientsResponse);
				byte[] integrityPassB = (byte[]) ois3a.readObject(); // read in integrity PassB
				sig.initVerify(encryptKey); // gets ready for verification using the public key of C
				sig.update(decryptedChal); //updates the data to be verified.
				boolean ifTrue = sig.verify(integrityPassB); // check if hash is the same
				System.out.println("Integrity PassB: " + ifTrue);
				System.out.println("Decrypting Integrity PassA");

				byte[] integrityPassA = (byte[]) ois2a.readObject(); // read in integrity PassA
				sig.initVerify(encryptKey); // gets ready for verification using public key
				sig.update(decryptedResp);
				boolean ifTrueb = sig.verify(integrityPassA); // check if hash is the same
				System.out.println("integrity PassA is...: " + ifTrueb);
				if(ifTrue == true)
				{
					if(ifTrueb == true)
					{
						challengeChecker = 1;
					}
				}
			}

			// Step 5: sending the encrypted response
			System.out.println("Sending encrypted response verifiation.");
			String responseToSend = aesAlgo.encrypt(clientsChallenge);
			dout4.writeUTF(responseToSend); 

			// Step 6: Encrypt Message with Session Key
			String plainText = "";
			plainText = msg_text.getText().trim();
			msg_area.setText(msg_area.getText().trim()+"\nServer:\t" + plainText);
			String encryptedText = aesAlgo.encrypt(plainText);
			jtaResult.setText("\nServer:\t" + encryptedText);


			dout3.writeUTF(encryptedText); // sending Encrypt Message with Session Key
			msg_text.setText("");
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	private void DecryptActionPerformed(ActionEvent evt) // Receives Decrypt the message with AES
	{
		try
		{
			// Excahnging RSA Public Key with Client
			System.out.println("Sending Server's RSA Public Key");
			ObjectOutputStream oos = new ObjectOutputStream(s4.getOutputStream());
			oos.writeObject(publicKey);
			oos.flush();
			System.out.println("Servers's RSA Public Key sent.");    

			// Receive RSA Public Key from Client
			System.out.println("Requesting Clients's RSA Public key");
			ObjectInputStream ois3 = new ObjectInputStream(s5.getInputStream());
			encryptKey = (PublicKey) ois3.readObject();
			System.out.println("Clients's RSA Public key received.");

			// STEP 2: Decipher step 1 and save Session Key 
			Signature sig = Signature.getInstance("SHA1WithRSA"); // choosing what hashing algorithm to use. SHA1 in this case
			ObjectInputStream ois1 = new ObjectInputStream(s4.getInputStream());
			ObjectInputStream ois2 = new ObjectInputStream(s5.getInputStream());
			String serversChallenge = null;
			byte[] decryptedChal = null;
			int challengeChecker = 0;
			while(challengeChecker == 0)
			{
				byte[] serverChallengeByte = (byte[]) ois1.readObject(); // read in challenge
				decryptedChal = rsaObj.privateKeyDecrypt(serverChallengeByte, privateModulus, privateExponent); // decrypt challenge
				serversChallenge = new String (decryptedChal);
				byte[] encryptedPassB = (byte[]) ois2.readObject(); // read in encrypted PassB
				sig.initVerify(encryptKey); // gets ready for verification using the public key
				sig.update(decryptedChal); //updates the data to be verified.
				boolean ifTrue = sig.verify(encryptedPassB);
				if(ifTrue == true)
				{
					challengeChecker = 1;
				}
			}
			passwordComplete = passA + serversChallenge; // create session key to be hashed
			System.out.println("Session Key is: " + passwordComplete);
			MessageDigest hash = MessageDigest.getInstance("SHA-1");
			hash.reset(); 
			hash.update(passwordComplete.getBytes("UTF-8")); // prepare to hash
			sessionKey = hash.digest(); 
			MessageDigest bringDown = MessageDigest.getInstance("MD5");
			bringDown.reset();
			bringDown.update(sessionKey);
			sessionPassword = bringDown.digest();
			aesAlgo = new AESAlgorithm(sessionPassword); 
			System.out.println("Session Key Saved.");

			// Step 3: Send challenge, response and encypted passA 
			byte[] passABytes = passA.getBytes(); // convert passA to bytes 
			byte[] encryptedChallenge = rsaObj.publicKeyEncrypt(passABytes, encryptKey);
			ObjectOutputStream oos1 = new ObjectOutputStream(s3.getOutputStream()); // set up output stream
			System.out.println("Sending the Challenge to Server.");
			oos1.writeObject(encryptedChallenge); 
			String encryptedPassB = aesAlgo.encrypt(serversChallenge); // encrypt the response with AES using Session Key 
			byte[] passBBytes = encryptedPassB.getBytes();//gets the response into a byte array
			byte[] encryptedResponse = rsaObj.publicKeyEncrypt(passBBytes, encryptKey); // encrypt the Response with RSA
			ObjectOutputStream oos2 = new ObjectOutputStream(s5.getOutputStream());
			oos2.writeObject(encryptedResponse); 

			// Hash, Digitally Sign then encrypt the PassA with RSA
			privateKey = rsaObj.getPrivateKey(privateModulus, privateExponent);
			Signature signa = Signature.getInstance("SHA1withRSA"); 
			signa.initSign(privateKey); 
			byte[] passAData = passA.getBytes(); // convert passA to bytes 
			signa.update(passAData); // updates passA to be signed
			byte[] signaBytes = signa.sign();  // Returns the signature bytes of all the data updated.

			ObjectOutputStream oos3 = new ObjectOutputStream(s4.getOutputStream()); // set up output stream
			System.out.println("Sending the PassB Integrity to Client.");
			oos3.writeObject(signaBytes); 
			signa.update(encryptedPassB.getBytes()); // updates encrypted passA to be signed
			byte[] signaPassB = signa.sign();  // Returns the signature bytes of the data updated.

			oos2.writeObject(signaPassB); // Send Integrity PassB over the socket to Server

			// Step 6: Encrypt Message with Session Key
			String magin = din3.readUTF(); 
			final String plainText = aesAlgo.decrypt(magin); 
			final String temp = msg_area.getText().trim()+ "\nClient:\t"+ plainText; 
			jtaResult.setText("\nClient:\t"+ magin);
			msg_area.setText(temp);
		} 
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	private void transferFileAESActionPerformed() {
		try{ // Encrypt file with AES and transfer file
			int fileSize = (int) f.length(); 
			byte[] myByteArray = new byte[(int) f.length()]; 
			dout4.writeInt(fileSize); 

			System.out.println(fileSize);
			// Create a BufferedInputStream object, initialising it with the user's selected file.
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f));
			// Reads bytes from the byte-input stream bis into myByteArray starting at 0.
			bis.read(myByteArray, 0, myByteArray.length);

			System.out.println("Byte array is: " + myByteArray);
			aesAlgo = new AESAlgorithm(sessionPassword);
			Cipher cipher = aesAlgo.encryptFile();
			OutputStream os = s4.getOutputStream();
			CipherOutputStream cos = new CipherOutputStream(os, cipher);
			cos.write(myByteArray, 0, myByteArray.length);
			cos.flush(); // forces any buffered output bytes to be written out.
			cos.close();

		}
		catch(Exception e){
			e.printStackTrace();
		} 
	}

	private void receiveFileAESActionPerformed() { // receive file
		try{           
			if(din4.available()==0) {
				return;
			} 
			JFileChooser chooser = new JFileChooser(); 
			chooser.showSaveDialog(null);
			f = chooser.getSelectedFile();
			int fileLength = din4.readInt(); 
			System.out.println("File equal to " + fileLength);
			
			byte[] myByteArray = new byte[fileLength];
			aesAlgo = new AESAlgorithm(sessionPassword); // set the new hashed session key
			Cipher cipher = aesAlgo.decryptFile();
			FileOutputStream fos = new FileOutputStream(f);
			CipherOutputStream cos = new CipherOutputStream(fos,cipher);
			byte[] buffer = new byte[8192]; // any size greater than 0 will work
			int count;
			while ((count = din4.read(buffer)) > 0)
			{
				cos.write(buffer, 0, count);
			}

			fos.flush();
			cos.close();
		} 
		catch(Exception e){
			e.printStackTrace(); 
		} 

	}
	
	private void encryptRSAActionPerformed(ActionEvent evt) {
		try // Encrypt a Message with RSA and Send
		{                      
			System.out.println("Requested Client's RSA Public Key");

			ObjectInputStream ois = new ObjectInputStream(s5.getInputStream()); //waiting 
			encryptKey = (PublicKey) ois.readObject(); // Saves Client's Public Key
			System.out.println("Received Client's Public Key");
			// Encryption of Message with Public Key
			String plainText = ""; 
			plainText = msg_text.getText().trim(); 
			msg_area.setText(msg_area.getText().trim()+"\nServer:\t" + plainText);
			System.out.println("About to encrypt using Client's Public Key.");
			byte[] dataToEncrypt = plainText.getBytes();
			byte[] encryptedData = rsaObj.publicKeyEncrypt(dataToEncrypt, encryptKey);
			jtaResult.setText("\nServer:\t" + encryptedData); // Display encrypted text
			dout5.writeInt(encryptedData.length); // send size of message
			dout5.write(encryptedData);
		} 
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	private void receiveRSAActionPerformed(ActionEvent evt) {                 
		try  // Receive & Decrypt RSA Encrypted message.
		{   
			System.out.println("Send Public Key to the client.");
			// Send RSA Public Key to Server
			ObjectOutputStream oos = new ObjectOutputStream(s5.getOutputStream());
			oos.writeObject(publicKey); //Send Server's Public Key
			oos.flush();
			System.out.println("Server's Public Key sent.");
			// Recieve message
			int length = din5.readInt();  // read length of incoming message
			if(length>0) 
			{
				byte[] message = new byte[length];
				din5.readFully(message, 0, message.length); // reads the message

				byte[] decryptedData = rsaObj.privateKeyDecrypt(message, privateModulus, privateExponent); // decrypts the encrypted data 
				final String temp = msg_area.getText().trim() + "\nClient:\t"+ new String(decryptedData); // Displays Client Message

				jtaResult.setText("\nClient:\t"+ message); // Display decrypted text to bottom pane

				//makes the GUI let free flow of messages without hanging
				SwingUtilities.invokeLater(new Runnable() {
					// except this is queued onto the event thread.
					public void run() {
						msg_area.setText(temp);
					}
				}); 
			}
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	public static void main(String args[]) {
		/* Create and display the form */
		java.awt.EventQueue.invokeLater(new Runnable() {
			public void run() {
				new chatServer().setVisible(true);
			} // end run
		});

		String magin = ""; // initialise magin
		try{
			ss = new ServerSocket(1234); //Creates where server socket is.(string)
			ss2 = new ServerSocket(1450); // Creates where server socket 2 is(file transfer)
			ss3 = new ServerSocket (1250); // creates where the server AES socket is (string)
			ss4 = new ServerSocket(1509); // Creates where the server AES socket is (file transfer)
			ss5 = new ServerSocket(1510); // Creates where the server RSA socket is (string)

			s = ss.accept(); 
			s2 = ss2.accept(); 
			s3 = ss3.accept(); //now client AES socket will connect with server AES socket (string)
			s4 = ss4.accept(); // now server will accept the connection for AES file transfer
			s5 = ss5.accept(); // now server will accept the connection for RSA (message)

			din = new DataInputStream(s.getInputStream()); // input stream for messages
			dout = new DataOutputStream(s.getOutputStream()); // output stream for messages

			din2 = new DataInputStream(s2.getInputStream()); // input stream for files
			dout2 = new DataOutputStream(s2.getOutputStream()); // output stream for files

			din3 = new DataInputStream(s3.getInputStream()); // input stream for AES String
			dout3 = new DataOutputStream(s3.getOutputStream()); // output stream for AES String

			din4 = new DataInputStream(s4.getInputStream()); // input stream for AES (File transfer)
			dout4 = new DataOutputStream(s4.getOutputStream()); // output stream for AES (File transfer)

			din5 = new DataInputStream(s5.getInputStream()); // input stream for RSA (message)
			dout5 = new DataOutputStream(s5.getOutputStream()); // output stream for RSA (message)            

			while(!magin.equals("exit"))
			{
				magin = din.readUTF(); 
				final String temp = msg_area.getText().trim()+"\nClient:\t"+magin; // Displays Client Message
				SwingUtilities.invokeLater(new Runnable() {
					// except this is queued onto the event thread.
					public void run() {
						msg_area.setText(temp);
					} // end run
				}); 
			} // end while
		} // end try
		catch(Exception e){ 
			e.printStackTrace(); 
		}
	}
}
