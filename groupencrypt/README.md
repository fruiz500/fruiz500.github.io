# GroupEncrypt
Encrypts/decrypts files for a group of users. A typical usage scenario would be adding zero-knowledge encryption to a file sharing service that does not have this feature natively.

This webapp is based on NaCl and SCRYPT. It uses the following open-source code from GitHub, included in the /lib-opensrc folder:

Tweet NaCl crypto library by Dmitry Chestnykh, v1.0.3. https://github.com/dchest/tweetnacl-js

scrypt-async-js KDF by Dmitry Chestnykh, v2.0.1. https://github.com/dchest/scrypt-async-js

User access to the encrypted output is controlled by the file GroupKeys.js, which must be edited for each particular implementation, although the page admin.html is designed so it can be done without editing the server code. This file, which should reside in the same folder as the index.html that loads the app, contains a single object GroupKeys with all the settings. First, the name of the group. This is used to salt the user passwords and make rainbow table attacks a little harder. Then the unique header that encrypted files begin with, and which the app uses to determine whether or not a file loaded onto it has been previously encrypted by the app. This entry is an array of numbers 0 to 255 representing bytes. The only important thing is that none of the files to be encrypted should begin with this sequence of bytes. The more bytes, the smaller the likelihood that this will happen. Finally, the file also contains the public keys of all the users in the group, up to a maximum of 255 active users, plus optional lists of users. Example:

var GroupKeys = {

"GroupName": "Sample Group",

"HeadTag": "[27,27,27,27,27,27,27]",

"Alice":
"it0oh6L44k2fnb4793kekbkanet8kdkfu9y5541kpojb3mk5om",

"Bob":
"acnkhinpurLgcjgcuLk1gwtn3zLyy68ystissirxumtxm4ctw6",

"Carol":
"r9t28eq9xa0L35wx66pngko0zao7p3r8kr3ahtjnw74aar3fgu",

"$Adam":
"wv6ndfmn8ntifp6k4xbncs3vjf8rxi8g7f9czfsab78vuyyxsa",

"==Girls==":
"Alice, Carol"

}

Notes: "$Adam" is a former user, kept so that files encrypted by this user can still be decrypted; the name begins with $. "==Girls==" is a list containing some active users.

This means that, during the app rollout period, each one of the users must load the app and enter a unique Password in the box, which won't be accepted if the matching public key is not in the database file. This displays his/her public key in a box below it, which then he/she copies and sends to a system Administrator by the most convenient means. Public keys are in base36 so they can be dictated over the phone (all letters lowercase, except for capital 'L' so it is not mistaken for number 1). Public keys are not secret, but if group members are going to run the app from file rather than from a server, you get a little extra security by sending those keys to the administrator through secure channels.

The Administrator then composes the permanent GroupKeys.js file with any text editor and distributes it to the users or uploads it to the server, or edits it via the special Administrator page loaded by clicking near the top of the user page, giving each user an identifying name, followed by a colon, and then his/her public key within quotes. Some entries can contain a list of user names instead. There must be a comma between entries, but spaces and carriage returns don't affect the result.

When encryption of a file takes place, the input file is encrypted so that each one of the selected users (default: all on the list) can decrypt the output file, and nobody else. This involves first doing symmetric encryption of the file with a random 32-byte message key, plus a random 24-byte nonce. Then the message key is encrypted with the symmetric key derived from each user's public key, obtained from the GroupKeys.js file, and the sender's private key, and the result is added to the encrypted file. Decryption by a particular user involves finding that user's encryted message key in the encrypted file, decrypting it with the combination of his/her private key, which derives from his/her Password, and the sender's public key (which is identified by its first 8 bytes being added to the encrypted message right before all the encrypted keys), and finally using the message key to decrypt the main file content.

In the event that a message has been encrypted by a user that has left the group, decryption is still possible if the former user's public key is still included in GroupKeys.js, with the name prefaced by a '$' character so this entry can be differentiated. In this case, the public key is never used for encryption, and the user's name cannot be listed as a recipient, but the public key is available for decryption.

In addition to the File by File mode described above, there is a Folder mode where the encryption of a particular file is done with a random symmetric key, and this key is added to the encryted file after encrypting it with a Folder Key common to a number of files. The Folder Key should be present in memory before encryption or decryption can proceed in this mode. Folder Keys are stored in special files encrypted in File by File mode, but containing no payload. Upon decryption, the message key is stored in memory to serve as Folder Key for files loaded after.

GroupEncrypt is based on the elliptic curve public key cryptography algorithms of the NaCl suite, which also includes XSalsa20 for symmetric encryption, plus the SCRYPT key derivation algorithm. Key length is 256 bits. The user-supplied Password is analyzed for strength, and the parameters of the SCRYPT algorithm are varied so that weaker Passwords are subjected to more rounds of key stretching. We call this the WiseHash algorithm, which makes the keyspace quite resistant to dictionary attack, since attackers are penalized for including weak Passwords in their search, or otherwise risk missing them. The encryption algorithm is similar to the Signed mode in PassLok, also by F. Ruiz, except that it uses no extra data such as user email, there is no padding that might contain a secret message, and the first 8 bytes of the sender's public key are added to speed up decryption. Files encrypted by this app cannot be decrypted in PassLok, and vice-versa.

Processing is done by the browser's built-in JavaScript engine, which makes the app very fast and cross-browser compatible. It can run on mobile devices as well. Files up to 1 GB in size can be handled, subject to memory availability. In this implementation, the data is input and output as local files, but it is easy to modify the code so the data is exchanged with a server instead. The format for the file data is uint8 arrays, each element containing one binary byte. The name of the input file data is fileInBin, that of the output data is fileOutBin.
