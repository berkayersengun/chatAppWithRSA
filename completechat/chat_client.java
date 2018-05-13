
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

public class chat_client extends JFrame {

	private static boolean encryptionEnabled;
	private static boolean fileEncryptionEnabled;
	static Socket s; // client socket. (s = socket)(string).
	static Socket s2; // client socket.(file)
	static Socket s3; // AES client socket.(string)
	static Socket s4;// AES client socket(file)
	static Socket s5; // RSA client socket.(string)

	static DataInputStream din; // din = data input
	static DataInputStream din2; // din2 = data input for file transfer
	static DataInputStream din3; // din3 = data input for AES string
	static DataInputStream din4; // din3 = data input for AES file transfer
	static DataInputStream din5; // din5 = data input for RSA message

	static DataOutputStream dout; // dout = data output
	static DataOutputStream dout2; // dout2 = data output for file transfer
	static DataOutputStream dout3; // dout3 = data output for AES string
	static DataOutputStream dout4; // dout3 = data output for AES file transfer
	static DataOutputStream dout5; // dout5 = data output for RSA message
	static File f; // Create f of type File. Needed for pathnames.

	static AESAlgorithm aesAlgo; // For AES
	static RSAAlgorithm rsaObj = new RSAAlgorithm(); // for RSA

	static BigInteger privateModulus; // hold teh modulus of the private key
	static BigInteger privateExponent; // hold the exponent of the private key
	static BigInteger publicModulus; // hold the modulus of the public key
	static BigInteger publicExponent; // hold the exponent of the public key

	static BigInteger serverPrivateExponent; // hold the private exponent of the server's key 
	static BigInteger serverPrivateModulus; // hold the private modulus for the server's key

	static PublicKey publicKey; // hold the Client's public key
	static PrivateKey privateKey; // hold the Client's private key

	static PublicKey encryptKey; // hold the server's public key

	private String passB = "ClientPassKey"; // Client's  Session Key    Note: this is a byte array
	private String passA; // Server's Session Key = new byte[] {'T','h','e','B','e','s','t','S'};
	private String passwordComplete; // This is the complete Session Key
	private byte[] sessionKey; // the mutually generated session key 
	private byte[] sessionPassword; // the MD5 hashed of sessionkey(SHA-1 Hash of key)


	// Variables declaration 
	private JButton Decrypt;
	private JToggleButton Encrypt;
	private JButton decryptRSA;
	private JButton encryptRSA;

	private JButton clientAttach, clientSendAttach;
	private JFileChooser fc;
	private static JTextField clientAttachDisplay;
	private static JTextArea jtaResult;
	private static JTextArea msg_area;
	private JButton msg_send;
	private static JTextField msg_text;
	private JButton receiveFileAES;
	private JButton recieveAttach;
	private JToggleButton EncryptFiles;


	public chat_client() {
		this.setDefaultCloseOperation(EXIT_ON_CLOSE);
		this.setMinimumSize(new Dimension(640,480));

		this.setLayout(new GridBagLayout());
		GridBagConstraints gridLayout = new GridBagConstraints();

		msg_area = new JTextArea(5, 20);
		msg_text = new JTextField(25);
		fc = new JFileChooser();
		clientAttachDisplay = new JTextField();
		clientAttachDisplay.setEditable(false);
		jtaResult = new JTextArea(5, 20);

		clientSendAttach = new JButton( "Send File", new ImageIcon(chat_client.class.getResource("upload.png"))); 
		recieveAttach = new JButton("Save File", new ImageIcon(chat_client.class.getResource("download.png")));
		clientAttach = new JButton( "Attach File", new ImageIcon(chat_client.class.getResource("attach2.png")));
		msg_send = new JButton( "Send Text", new ImageIcon(chat_client.class.getResource("send.png")));

		Encrypt = new JToggleButton("AES Encrypt");
		Decrypt = new JButton("AES Decrypt");
		EncryptFiles = new JToggleButton("Encrypt File");
		receiveFileAES = new JButton("Decrypt File");
		encryptRSA = new JButton("RSA Encrypt");
		decryptRSA = new JButton("RSA Decrypt");

		setDefaultCloseOperation(EXIT_ON_CLOSE);
		setTitle("ChatBackground");
		setName("Client");
		setResizable(false);

		this.setTitle("Chat Client Window");
		this.setVisible(true);

		msg_area.setEditable(false);
		msg_area.setLineWrap(true);

		msg_send.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				msg_sendActionPerformed(evt);
			}
		});


		clientAttach.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				clientAttachActionPerformed(evt);
			}
		});

		clientSendAttach.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				clientSendAttachActionPerformed(evt);
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
	               String temp = msg_area.getText().trim()+"\nClient:\t"+"[File Encryption Started]";
	               SwingUtilities.invokeLater(new Runnable() {
	       			// except this is queued onto the event thread.
	       			public void run() {
	       				msg_area.setText(temp);
	       			}
	       		});
					try {
						dout.writeUTF("[File Encryption Started]");
					} catch (Exception err) {
						err.printStackTrace();
					}
	            } else {
	            	fileEncryptionEnabled = false;
	            	msg_area.setText(msg_area.getText().trim()+"\nClient:\t"+"[File Encryption Ended]");
					try {
						dout.writeUTF("[File Encryption Ended]");
					} catch (Exception err) {
						err.printStackTrace();
					}
	            }
	         }
	      });
		Decrypt.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				DecryptActionPerformed(evt);
			}
		});
		
		encryptRSA.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				encryptRSAActionPerformed(evt);
			}
		});

		decryptRSA.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				decryptRSAActionPerformed(evt);
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
		this.add(clientAttachDisplay, gridLayout);

		gridLayout.gridx = 4;
		gridLayout.gridy = 6;
		gridLayout.weightx = 0;
		gridLayout.gridwidth = 1;
		this.add(msg_send, gridLayout);

		gridLayout.gridx = 5;
		gridLayout.gridy = 7;
		gridLayout.weightx = 0;
		gridLayout.gridwidth = 1;
		this.add(clientSendAttach, gridLayout);

		gridLayout.gridx = 4;
		gridLayout.gridy = 7;
		gridLayout.weightx = 0;
		gridLayout.gridwidth = 1;
		this.add(clientAttach, gridLayout);

		gridLayout.gridx = 5;
		gridLayout.gridy = 6;
		gridLayout.weightx = 0;
		gridLayout.gridwidth = 1;
		this.add(recieveAttach, gridLayout);

		try
		{
			rsaObj.generateKeys(); // generate keys for RSA
			privateModulus = rsaObj.getPrivateModulus(); // get the private modulus of the object
			privateExponent = rsaObj.getPrivateExponent(); // get the private exponent of the object
			publicModulus = rsaObj.getPublicModulus(); // get the public modulus of the object
			publicExponent = rsaObj.getPublicExponent(); // get the public exponent of the object

			publicKey = rsaObj.getPubKey(publicModulus, publicExponent); //create public key
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	public Key generateKey() throws NoSuchAlgorithmException // code to generate key for AES
	{
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		SecureRandom random = new SecureRandom();
		kg.init(random);
		return kg.generateKey();
	}

	private void msg_sendActionPerformed(java.awt.event.ActionEvent evt) { // Method for Send button
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

	private void clientAttachActionPerformed(java.awt.event.ActionEvent evt)
	{
		JFileChooser chooser = new JFileChooser(); // create object of JFileChooser
		chooser.showOpenDialog(null); // choose file
		f = chooser.getSelectedFile(); // assign the file equal to f
		String filename = f.getAbsolutePath(); // filename = the path of f.
		clientAttachDisplay.setText(filename); // display directory of f in attach window

	}

	private void clientSendAttachActionPerformed(java.awt.event.ActionEvent evt) {// Send Attachment Button    
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
		String temp = msg_area.getText().trim()+"\nClient:\t"+"[Sending File]";
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
		String temp = msg_area.getText().trim()+"\nClient:\t"+"[File Received]";
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

	private void EncryptActionPerformed() {
		try
		{
			System.out.println("Requesting Server's RSA Public");
			// Receive RSA Public Key from Server
			ObjectInputStream ois = new ObjectInputStream(s4.getInputStream());
			encryptKey = (PublicKey) ois.readObject(); // Server's Public Key recieved
			System.out.println("Server's RSA Public key received.");

			System.out.println("Sending RSA Public Key to Server");
			// Send RSA Public Key to Server
			ObjectOutputStream oos = new ObjectOutputStream(s5.getOutputStream());
			oos.writeObject(publicKey); //Send Client's Public Key
			oos.flush();
			System.out.println("Client RSA Public Key Sent."); 

			//STEP 1: Hash the Pass A, Digitaly Sign with private key and Encrypt with RSA public key
			privateKey = rsaObj.getPrivateKey(privateModulus, privateExponent);
			byte[] passBData = passB.getBytes(); // convert passA to bytes 
			Signature sig = Signature.getInstance("SHA1WithRSA"); // choosing what hashing algorithm to use. SHA1 in this case
			sig.initSign(privateKey); // gets ready for signing using the private key
			sig.update(passBData); // updates passA to be signed
			byte[] signatureBytes = sig.sign();  // Returns the signature bytes of all the data updated.

			byte[] encryptedChallenge = rsaObj.publicKeyEncrypt(passBData, encryptKey); // encrypt challenge RSA
			ObjectOutputStream oos1 = new ObjectOutputStream(s4.getOutputStream());
			System.out.println("Sending the Challenge to Server.");
			oos1.writeObject(encryptedChallenge); // Send Challenge over the socket to Client
			ObjectOutputStream oos2 = new ObjectOutputStream(s5.getOutputStream());
			System.out.println("Sending the Encrypted Digitally Signed Hashed PassA to Server.");
			oos2.writeObject(signatureBytes); // Send Encrypted Digitally Signed Hashed PassA over the socket to Client
			System.out.println("Step 1 Completed.");

			//STEP 4: Decipher data sent from Client and save session key
			ObjectInputStream ois1a = new ObjectInputStream(s3.getInputStream());
			ObjectInputStream ois2a = new ObjectInputStream(s5.getInputStream());
			ObjectInputStream ois3a = new ObjectInputStream(s4.getInputStream());

			String serversChallenge = null;
			String serversResponse = null;
			byte[] decryptedChal = null;
			byte[] decryptedResp = null;
			byte[] decryptedIntPassBr = null;
			byte[] decryptedIntPassAr = null;
			int challengeChecker = 0; // used to see if challenge is valid
			while(challengeChecker == 0)
			{
				System.out.println("Decrypting Challenge from Client");
				byte[] clientChallenge = (byte[]) ois1a.readObject(); // read in challenge
				decryptedChal = rsaObj.privateKeyDecrypt(clientChallenge, privateModulus, privateExponent); // decrypt challenge
				serversChallenge = new String (decryptedChal); // Convert challenge back to string
				System.out.println("Pass B is: " + serversChallenge);
				System.out.println("The next step is to Decrypt Response from Client");
				passwordComplete = serversChallenge + passB; // create session key to be hashed
				System.out.println("Session Key is: " + passwordComplete);
				MessageDigest hash = MessageDigest.getInstance("SHA-1"); // hash the password using SHA1
				hash.reset(); // reset messagedigest so it can hash new value
				hash.update(passwordComplete.getBytes()); // prepare to hash
				sessionKey = hash.digest(); // hash the session key
				MessageDigest bringSios = MessageDigest.getInstance("MD5"); // bring the Hashed password down to 16 bytes 
				bringSios.reset();
				bringSios.update(sessionKey); 
				sessionPassword = bringSios.digest(); // hash the hashed sessionkey
				aesAlgo = new AESAlgorithm(sessionPassword); 
				System.out.println("Session Key Saved.");
				System.out.println("Decrypting Client's Response with session key.");
				byte[] clientResponse = (byte[]) ois2a.readObject(); // read in Response
				decryptedResp = rsaObj.privateKeyDecrypt(clientResponse, privateModulus, privateExponent); // decrypt response with rsa
				serversResponse = new String (decryptedResp);
				String decryptedPassA = aesAlgo.decrypt(serversResponse); // decrypt text and assign to plainText
				System.out.println("Decrypting Integrity PassB");

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
			String responseToSend = aesAlgo.encrypt(serversChallenge); // encrypt with Session key
			dout4.writeUTF(responseToSend); // sending the encrypted response

			// Step 6: Encrypt Message with Session Key
			String plainText = ""; // initilaise the String Variable PlainText.
			plainText = msg_text.getText().trim(); // get the text from where you typed
			msg_area.setText(msg_area.getText().trim()+"\nClient:\t" + plainText); // print  plain text on server side
			String encryptedText = aesAlgo.encrypt(plainText); // set 'encryptedText' to the encrypted version of plainText
			jtaResult.setText("\nClient:\t" + encryptedText); // Display encrypted text in the window pane
			dout3.writeUTF(encryptedText); // sending the encrypted server message to the client. (Creating a unicode string)
		} // end try
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	private void DecryptActionPerformed(ActionEvent evt) {
		try
		{
			// Exchanging RSA Public Ket with Server
			System.out.println("Requested Client's RSA Public Key");
			// Send RSA Public Key to Server
			ObjectOutputStream oos = new ObjectOutputStream(s4.getOutputStream());
			oos.writeObject(publicKey); //Send Client's Public Key to server
			oos.flush();
			System.out.println("Client's RSA Public Key Sent.");    

			// Receive RSA Public Key from Client
			System.out.println("Requesting Server's RSA Public key");
			// Receive RSA Public Key from Server
			ObjectInputStream ois3 = new ObjectInputStream(s5.getInputStream());
			encryptKey = (PublicKey) ois3.readObject(); // recieve Server's Public Key 
			System.out.println("Server's RSA Public key received.");

			// STEP 2: Decipher step 1 and save Session Key 
			Signature sig = Signature.getInstance("SHA1WithRSA"); // choosing what hashing algorithm to use. SHA1 in this case
			ObjectInputStream ois1 = new ObjectInputStream(s4.getInputStream());
			ObjectInputStream ois2 = new ObjectInputStream(s5.getInputStream());
			String clientsChallenge = null;
			byte[] decryptedChal = null;
			int challengeChecker = 0; // used to see if challenge is valid
			while(challengeChecker == 0)
			{
				byte[] clientChallenge = (byte[]) ois1.readObject(); // reads the challenge
				decryptedChal = rsaObj.privateKeyDecrypt(clientChallenge, privateModulus, privateExponent); // decrypt challenge from server
				clientsChallenge = new String (decryptedChal);
				System.out.println("Pass B is: " + clientsChallenge);

				byte[] encryptedPassA = (byte[]) ois2.readObject(); // read in encrypted PassA
				sig.initVerify(encryptKey); // gets ready for verification using the public key
				sig.update(decryptedChal); //updates the data to be verified.
				boolean ifTrue = sig.verify(encryptedPassA); // check if hash is the same
				System.out.println("Challenge is: " + ifTrue);

				if(ifTrue == true)
				{
					challengeChecker = 1;
				}
			}

			passwordComplete = clientsChallenge + passB; // create session key to be hashed
			System.out.println("Session Key is: " + passwordComplete);
			MessageDigest hash = MessageDigest.getInstance("SHA-1");
			hash.reset(); // reset messagedigest so it can hash new value
			hash.update(passwordComplete.getBytes("UTF-8")); // prepare to hash
			sessionKey = hash.digest(); // hash the session key
			System.out.println("Session Key be: " + sessionKey);
			System.out.println("Bring SHA1 down to 16 bytes");
			MessageDigest bringDown = MessageDigest.getInstance("MD5");
			bringDown.reset();
			bringDown.update(sessionKey);
			sessionPassword = bringDown.digest(); // hash the hash
			System.out.println("Session Key hashed again. Down to 16 bytes now.");

			aesAlgo = new AESAlgorithm(sessionPassword); // set the new hashed 16 byte session key
			System.out.println("Session Key Saved.");

			// Step 3: Send challenge, response and encypted passB
			System.out.println("Beginning Step 3.");
			byte[] passB_Bytes = passB.getBytes(); // convert passB to bytes 
			byte[] encryptedChallenge = rsaObj.publicKeyEncrypt(passB_Bytes, encryptKey); // encrypt challenge RSA
			ObjectOutputStream oos1 = new ObjectOutputStream(s3.getOutputStream()); // set up output stream
			oos1.writeObject(encryptedChallenge); 

			String encryptedPassA = aesAlgo.encrypt(clientsChallenge); // encrypt the response with AES using Session Key 
			byte[] passBBytes = encryptedPassA.getBytes();//gets the response into a byte array
			byte[] encryptedResponse = rsaObj.publicKeyEncrypt(passBBytes, encryptKey); // encrypt the Response with RSA
			ObjectOutputStream oos2 = new ObjectOutputStream(s5.getOutputStream());
			oos2.writeObject(encryptedResponse);
			System.out.println("The next step is to Hash, Digitally Sign then encrypt the PassB with RSA.");
			privateKey = rsaObj.getPrivateKey(privateModulus, privateExponent);
			Signature signa = Signature.getInstance("SHA1withRSA"); 
			signa.initSign(privateKey); 
			byte[] passBData = passB.getBytes(); 
			signa.update(passBData); // updates passB to be signed
			byte[] signaBytes = signa.sign();  // Returns the signature bytes of all the data updated.
			ObjectOutputStream oos3 = new ObjectOutputStream(s4.getOutputStream()); // set up output stream
			oos3.writeObject(signaBytes); 
			signa.update(encryptedPassA.getBytes());
			byte[] signaPassB = signa.sign();  // Returns the signature bytes of the data updated.
			oos2.writeObject(signaPassB); // SendS


			// Step 6: Encrypt Message with Session Key
			String msgin = din3.readUTF(); 
			final String plainText = aesAlgo.decrypt(msgin);
			final String temp = msg_area.getText().trim()+"\nServer:\t"+plainText; 
			jtaResult.setText("\nServer:\t" + msgin); 
			msg_area.setText(temp);
		} 
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	private void transferFileAESActionPerformed(){ 		
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
			} // end if
			JFileChooser chooser = new JFileChooser();
			chooser.showSaveDialog(null); 
			f = chooser.getSelectedFile(); 

			int fileLength = din4.readInt(); 

			byte[] myByteArray = new byte[fileLength];
			aesAlgo = new AESAlgorithm(sessionPassword); // set the new hashed session key
			// makes cipher with key
			Cipher cipher = aesAlgo.decryptFile();

			// Create file output stream fos to write to the file specified by f
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
		} // end try

		catch(Exception e){
			e.printStackTrace();
		}

	}
	
	private void encryptRSAActionPerformed(ActionEvent evt) {
		try // Encrypt a Message with RSA and Send
		{
			System.out.println("Requested Server's Public key");

			ObjectInputStream ois = new ObjectInputStream(s5.getInputStream());
			encryptKey = (PublicKey) ois.readObject(); // Server's Public Key
			System.out.println("Server's Public key received.");
			String plainText = ""; 
			plainText = msg_text.getText().trim(); 
			msg_area.setText(msg_area.getText().trim()+"\nClient:\t" + plainText);
			System.out.println("About to Encrypt using Server's Public Key");
			byte[] dataToEncrypt = plainText.getBytes();//gets the data into a byte array
			byte[] encryptedData = rsaObj.publicKeyEncrypt(dataToEncrypt, encryptKey); 
			System.out.println("Message Encrypted using Server's Public Key");
			jtaResult.setText("\nClient:\t" + encryptedData); 
			dout5.writeInt(encryptedData.length); // send size of message
			dout5.write(encryptedData);
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	private void decryptRSAActionPerformed(ActionEvent evt) {
		try   // Receive & Decrypt RSA Encrypted message.
		{    
			System.out.println("Send public Key to the Server");
			ObjectOutputStream oos = new ObjectOutputStream(s5.getOutputStream());
			oos.writeObject(publicKey); //Send Client's Public Key
			oos.flush();
			System.out.println("Client's Public Key Sent.");
			int length = din5.readInt(); 
			if(length>0) 
			{
				byte[] message = new byte[length];
				din5.readFully(message, 0, message.length);
				byte[] decryptedData = rsaObj.privateKeyDecrypt(message, privateModulus, privateExponent); // decrypts the encrypted data        
				final String temp = msg_area.getText().trim()+ "\nServer:\t"+ new String(decryptedData); // Displays Client Message

				jtaResult.setText("\nServer:\t"+ message);   
				SwingUtilities.invokeLater(new Runnable() {
					public void run() {
						msg_area.setText(temp);
					} // end run
				}); 
			} 
		} 
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	public static void main(String args[]) {
		java.awt.EventQueue.invokeLater(new Runnable() {
		
			public void run() {
				new chat_client().setVisible(true);
			} // end run
		});

		try{
			s = new Socket("127.0.0.1",1234);
			din = new DataInputStream(s.getInputStream()); // input stream for messages
			dout = new DataOutputStream(s.getOutputStream()); // output stream for messages

			s2 = new Socket("127.0.0.1",1450); // port for file transfer
			din2 = new DataInputStream(s2.getInputStream()); // input stream for files
			dout2 = new DataOutputStream(s2.getOutputStream()); // output stream for files

			s3 = new Socket("127.0.0.1",1250); // port for AES string
			din3 = new DataInputStream(s3.getInputStream()); // input stream for AES Strimg
			dout3 = new DataOutputStream(s3.getOutputStream()); // output stream for AES String

			s4 = new Socket("127.0.0.1",1509); // port for AES file transfer
			din4 = new DataInputStream(s4.getInputStream()); // input stream for AES file transfer
			dout4 = new DataOutputStream(s4.getOutputStream()); // output AES file transfer

			s5 = new Socket("127.0.0.1",1510); // port for RSA Message
			din5 = new DataInputStream(s5.getInputStream()); // input stream for RSA Message
			dout5 = new DataOutputStream(s5.getOutputStream()); // output stream for RSA Message        

			String msgin = ""; // initialise msgin
			while(!msgin.equals("exit")){
				if(din.available() > 0){
					msgin = din.readUTF(); // returns a unicode string (UTF 8)
					// used to prevent GUI freeze
					final String temp = msg_area.getText().trim()+"\nServer:\t"+msgin; // Displays Server Message
					SwingUtilities.invokeLater(new Runnable() {
						// except this is queued onto the event thread.
						public void run() {
							msg_area.setText(temp);
						}
					});
				}
			}
		}
		catch(Exception e){
			e.printStackTrace(); // It tells you what happened and where in the code it happened.
		}
	} 
}
