//for showing and hiding text in the Password box
function showPwd(){
	if(pwdBox.type == "password"){
		pwdBox.type = "text";
		showPwdMode.src = "images/hide-24.png"
	}else{
		pwdBox.type = "password";
		showPwdMode.src = "images/eye-24.png"
	}
	keyStrength(pwdBox.value,true)
}

//to display password strength
function pwdKeyup(evt){
	evt = evt || window.event;
	var key = evt.keyCode || evt.which || evt.keyChar;
	if(key == 13){acceptPwd()} else{
		 if(pwdBox.value){
			 keyStrength(pwdBox.value,true)
		 }else{
			 pwdMsg.textContent = "Please enter your Password"
		 }
	}
}

//makes 'pronounceable' hash of a string, so user can be sure the password was entered correctly
var vowel = 'aeiou',
	consonant = 'bcdfghjklmnprstvwxyz',
	hashiliTimer;
function hashili(msgID,string){
	var element = document.getElementById(msgID);
	clearTimeout(hashiliTimer);
	hashiliTimer = setTimeout(function(){
		if(!string.trim()){
			element.innerText += ''
		}else{
			var code = nacl.hash(nacl.util.decodeUTF8(string.trim())).slice(-2),			//take last 4 bytes of the SHA512		
				code10 = ((code[0]*256)+code[1]) % 10000,		//convert to decimal
				output = '';

			for(var i = 0; i < 2; i++){
				var remainder = code10 % 100;								//there are 5 vowels and 20 consonants; encode every 2 digits into a pair
				output += consonant[Math.floor(remainder / 5)] + vowel[remainder % 5];
				code10 = (code10 - remainder) / 100
			}
			element.textContent += '\r\n' + output
		}
	}, 1000);						//one second delay to display hashili
}

//The rest is modified from WiseHash. https://github.com/fruiz500/whisehash
//function to test key strength and come up with appropriate key stretching. Based on WiseHash
function keyStrength(pwd,display) {
	if(pwd){
		var entropy = entropycalc(pwd);
	}else{
		document.getElementById('pwdMsg').textContent = 'Type your Password in the box';
		return
	}
	
	if(entropy == 0){
		var msg = 'This is a known bad password!';
		var colorName = 'magenta'
	}else if(entropy < 20){
		var msg = 'Terrible!';
		var colorName = 'magenta'
	}else if(entropy < 40){
		var msg = 'Weak!';
		var colorName = 'red'
	}else if(entropy < 60){
		var msg = 'Medium';
		var colorName = 'darkorange'
	}else if(entropy < 90){
		var msg = 'Good!';
		var colorName = 'green'
	}else if(entropy < 120){
		var msg = 'Great!';
		var colorName = 'blue'
	}else{
		var msg = 'Overkill  !';
		var colorName = 'cyan'
	}

	var iter = Math.max(1,Math.min(20,Math.ceil(24 - entropy/5)));			//set the scrypt iteration exponent based on entropy: 1 for entropy >= 120, 20(max) for entropy <= 20
	if(display){	
		msg = 'entropy ' + Math.round(entropy*100)/100 + ' bits. ' + msg;
	
		pwdMsg.textContent = msg;
		pwdMsg.style.color = colorName;
		hashili('pwdMsg',pwd)
	}
	return iter
}

//takes a string and calculates its entropy in bits, taking into account the kinds of characters used and parts that may be in the general wordlist (reduced credit) or the blacklist (no credit)
function entropycalc(pwd){

//find the raw Keyspace
	var numberRegex = new RegExp("^(?=.*[0-9]).*$", "g");
	var smallRegex = new RegExp("^(?=.*[a-z]).*$", "g");
	var capRegex = new RegExp("^(?=.*[A-Z]).*$", "g");
	var base64Regex = new RegExp("^(?=.*[/+]).*$", "g");
	var otherRegex = new RegExp("^(?=.*[^a-zA-Z0-9/+]).*$", "g");

	pwd = pwd.replace(/\s/g,'');										//no credit for spaces

	var Ncount = 0;
	if(numberRegex.test(pwd)){
		Ncount = Ncount + 10;
	}
	if(smallRegex.test(pwd)){
		Ncount = Ncount + 26;
	}
	if(capRegex.test(pwd)){
		Ncount = Ncount + 26;
	}
	if(base64Regex.test(pwd)){
		Ncount = Ncount + 2;
	}
	if(otherRegex.test(pwd)){
		Ncount = Ncount + 31;											//assume only printable characters
	}

//start by finding words that might be on the blacklist (no credit)
	var pwd = reduceVariants(pwd);
	var wordsFound = pwd.match(blackListExp);							//array containing words found on the blacklist
	if(wordsFound){
		for(var i = 0; i < wordsFound.length;i++){
			pwd = pwd.replace(wordsFound[i],'');						//remove them from the string
		}
	}

//now look for regular words on the wordlist
	wordsFound = pwd.match(wordListExp);									//array containing words found on the regular wordlist
	if(wordsFound){
		wordsFound = wordsFound.filter(function(elem, pos, self) {return self.indexOf(elem) == pos;});	//remove duplicates from the list
		var foundLength = wordsFound.length;							//to give credit for words found we need to count how many
		for(var i = 0; i < wordsFound.length;i++){
			pwd = pwd.replace(new RegExp(wordsFound[i], "g"),'');									//remove all instances
		}
	}else{
		var foundLength = 0;
	}

	pwd = pwd.replace(/(.+?)\1+/g,'$1');								//no credit for repeated consecutive character groups

	if(pwd != ''){
		return (pwd.length*Math.log(Ncount) + foundLength*Math.log(wordLength + blackLength))/Math.LN2
	}else{
		return (foundLength*Math.log(wordLength + blackLength))/Math.LN2
	}
}

//take into account common substitutions, ignore spaces and case
function reduceVariants(string){
	return string.toLowerCase().replace(/[óòöôõo]/g,'0').replace(/[!íìïîi]/g,'1').replace(/[z]/g,'2').replace(/[éèëêe]/g,'3').replace(/[@áàäâãa]/g,'4').replace(/[$s]/g,'5').replace(/[t]/g,'7').replace(/[b]/g,'8').replace(/[g]/g,'9').replace(/[úùüû]/g,'u');
}

//stretches a password string with a salt string to make a 256-bit Uint8Array Key
function wiseHash(pwd,salt){
	var iter = keyStrength(pwd,false),
		secArray = new Uint8Array(32),
		keyBytes;

	scrypt(pwd,salt,iter,8,32,0,function(x){keyBytes=x;});		//does a variable number of rounds of scrypt, using nacl libraries

	for(var i=0;i<32;i++){
			secArray[i] = keyBytes[i]
	}
	return secArray
}

//global variables used for key box expiration
var keytimer = 0,
    keytime = new Date().getTime();

//the first two derive from the Key after running through scrypt stretching.
var myKey,			//uint256 bit arrays
	myLock,
	folderKey,
	myName;			//string

//If the timer has run out the Password is deleted from its box, and stretched keys are deleted from memory
function refreshKey(){
	clearTimeout(keytimer);
	var period = 300000;

//start timer to erase Key
	keytimer = setTimeout(function() {
		resetKeys();
	}, period);

	keytime = new Date().getTime();

//now check that the binary Key is still there, and return false if not
	if (!myKey){
		pwdMsg.textContent = 'Please enter your secret Key and press Accept';
		fileMsg.textContent = 'Please enter your secret Key and press Accept';
		return false
	}
	return true
}

//resets the Keys in memory when the timer ticks off; hide extra options as well
function resetKeys(){
	myKey = '';
	myLock = '';
	pwdBox.value = '';
	folderKey = '';
	myName = '';
	fileMsg.textContent = 'Enter your Password first';
	pwdMsg.style.color = 'red';
	pwdMsg.textContent = 'Password forgotten due to inactivity. Please enter it again';
	makeKeyBtn.textContent = 'New Folder Key';
	fileImg.src = 'images/key-white.png';
	fileLbl.title = "drop a Folder Key here";
	fileIn.type = '';
	fileIn.type = 'file';								//resets file input
	pwdArea.style.display = '';
	step1.style.display = '';
	step2.style.display = '';
	step3.style.display = '';
	fileArea.style.display = '';
	singleMode.checked = false;
	selectArea.style.display = '';
    deselectList();
    updateUsers()
}
//executed when user presses Accept button; creates uint8 secret arrays, displays Lock, and starts timer to delete said arrays
function acceptPwd(){
	clearTimeout(hashiliTimer);
	var key = pwdBox.value.trim();
    if(key == ''){
        pwdMsg.textContent = 'Please enter your Password';
        return
    }
    if(key.length < 4){
        pwdMsg.textContent = 'This Password is too short!';
        return
    }

	pwdMsg.textContent = '';
    var blinker = document.createElement('span'),
        msgText = document.createElement('span');
    blinker.className = "blink";
    blinker.textContent = "LOADING...";
    msgText.textContent = " for best speed, use at least a Medium strength Password";
    pwdMsg.appendChild(blinker);
    pwdMsg.appendChild(msgText);

	//now make the binary secret Key from the password
	setTimeout(function(){
		myKey = wiseHash(key,groupName);									//global variable groupName is used as salt
		myLock = makePub(myKey);											//matching public key
		folderKey = '';														//remove if cached
		var myEzLock = changeBase(nacl.util.encodeBase64(myLock).replace(/=+$/,''), base64, base36);	//for display as text; easy to dictate
		while(myEzLock.length < 50) myEzLock = 'a' + myEzLock;											//prepend zeroes to reach max length
		var myIndex = lockIndex(myLock,locks,32);							//check for active user status; use all bytes
		if(myIndex == -1){
			pwdMsg.style.color = 'red';
			pwdMsg.textContent = 'This Password does not belong to any active users, but its matching ID is shown below.\r\nTo gain access, send this ID to the Administrator:\r\n';
			var publicKey = document.createElement('span');
			setTimeout(function(){publicKey.style.color = 'black'},0);
			publicKey.textContent = myEzLock;
			pwdMsg.appendChild(publicKey);
			return
		}
		myName = users[myIndex];							//global variable
		fileMsg.style.color = 'blue';
		fileMsg.textContent = 'Password accepted for user ' + myName;
		pwdBox.value = '';																		//all done, so empty the password box
		pwdMsg.textContent = '';
		pwdArea.style.display = 'none';
		step1.style.display = 'none';
		step2.style.display = '';
		step3.style.display = '';
		fileArea.style.display = 'block';
		userListArea.style.display = 'block';
		refreshKey()					//start timer to erase secret keys
	},10)								//short delay to allow blinking message to load
}

//to display public keys as text
const base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
	base36 = "abcdefghijkLmnopqrstuvwxyz0123456789";

//from http://snippetrepo.com/snippets/bignum-base-conversion, by kybernetikos
function changeBase(number, inAlpha, outAlpha) {
	var targetBase = outAlpha.length,
		originalBase = inAlpha.length;
    var result = "";
    while (number.length > 0) {
        var remainingToConvert = "", resultDigit = 0;
        for (var position = 0; position < number.length; ++position) {
            var idx = inAlpha.indexOf(number[position]);
            if (idx < 0) {
                throw new Error('Symbol ' + number[position] + ' from the'
                    + ' original number ' + number + ' was not found in the'
                    + ' alphabet ' + inAlpha);
            }
            var currentValue = idx + resultDigit * originalBase;
            var remainDigit = Math.floor(currentValue / targetBase);
            resultDigit = currentValue % targetBase;
            if (remainingToConvert.length || remainDigit) {
                remainingToConvert += inAlpha[remainDigit];
            }
        }
        number = remainingToConvert;
        result = outAlpha[resultDigit] + result;
    }
    return result;
}

//loads multiple files and processes them for encryption or decryption; adapted from https://ourcodeworld.com/articles/read/1438/how-to-read-multiple-files-at-once-using-the-filereader-class-in-javascript
function loadFiles(ev){
//	let files = ev.currentTarget.files;
	let files = fileIn.files;
    let readers = [];
	let fileNames = [];

	// Abort if there were no files selected
	if(!files.length) return;
	
	//store names
	for(var i = 0; i < files.length; i++){
		fileNames.push(files[i].name)
	}

    // Store promises in array
    for(let i = 0;i < files.length;i++){
        readers.push(readFileAsArrayBuffer(files[i]));
    }
                
    // Trigger Promises
    Promise.all(readers).then((values) => {
                    // Values will be an array that contains an item
                    // with the data of every selected file
                    // ["File1 Content", "File2 Content" ... "FileN Content"]

		for(var i = 0; i < values.length; i++){

			var fileInBin = new Uint8Array(values[i]),
				fileOutName = fileNames[i];
			var isEncrypted = true;													//check that the file begins with the encrypt marker
			for(var j = 0; j < headTag.length; j++){
				if(fileInBin[j] != headTag[j]){
					isEncrypted = false;
					break
				}
			}

			if(isEncrypted){													//call encryption or decryption depending on how the file starts
				fileOutName = fileOutName.slice(0,-6);
				decrypt(fileInBin,fileOutName)									//mode determined within decrypt function
			}else{
				fileOutName = fileOutName + '.crypt';
				encrypt(fileInBin,fileOutName)									//mode determined within encrypt function
			}
		}
    });
	fileIn.type = '';
	fileIn.type = 'file';								//resets file input
}

//makes a promise to read the binary data of a file
function readFileAsArrayBuffer(file){
	return new Promise(function(resolve,reject){
		let fr = new FileReader();

		fr.onload = function(){
			resolve(fr.result);
		};

		fr.onerror = function(){
			reject(fr);
		};

		fr.readAsArrayBuffer(file);
	});
}

//checks that a certain array is present in a certain array of arrays, up to a certain length
function lockIndex(lock,array,legth2check){
	for(var i = 0; i < array.length; i++){
		var isThisLock = true;
		for(var j = 0; j < legth2check; j++){
			isThisLock = isThisLock && (lock[j] == array[i][j])			//check first few elements; return false if even one does not match
		}
		if(isThisLock) return i											//return index in array if found
	}
	return -1														  //lock not found
}

//makes a key file, by encrypting an empty array in Signed mode
function makeKeyFile(){
	if(folderKey){
		var alertMsg = "Only the Administrator should update Folder Key files. Users must be selected first. Are sure you want to continue?"
	}else{
		var alertMsg = "Only the Administrator should make new Folder Key files. Users must be selected first. Are sure you want to continue?\r\n\r\nA new Folder Key makes files encrypted with a previous key undecryptable"
	}
	if(!confirm(alertMsg)) return;

	encrypt([],'_FolderKey.crypt')		//empty input for a folder key
}

//crypto functions; similar to Signed mode in PassLok, except that 8 bytes of sender's public key are added in order to identify this user
function encrypt(fileInBin, fileOutName){
	if(!refreshKey()) return;			//check that the Key is active and stop if not
	if(locks.length <= 0) return;

	startBlink(true);

	setTimeout(function(){										//delay to allow blinker to start

		var isKeyFile = (fileInBin.length == 0);				//folder key file if input is empty

		if(!singleMode.checked && !isKeyFile){						//folder mode: symmetric encryption using folderKey as key
			
			if(!folderKey){
				fileMsg.style.color = 'red';
				fileMsg.textContent = 'To encrypt files in Folder mode, you must load an encrypted Folder Key first'
				return
			}

			var	msgKey = nacl.randomBytes(32),								//message key for symmetric encryption
				nonce = nacl.randomBytes(24);								//nonce so each encryption is unique; 24 bytes

			var msgKeyCipher = nacl.secretbox(msgKey,nonce,folderKey),				//message key encrypted with folder key
				cipher = nacl.secretbox(fileInBin,nonce,msgKey);					//message encrypted with message key

			var fileOutBin = concatUi8([headTag,[0],nonce,msgKeyCipher,cipher]);		//start with header, a zero byte, and the nonce, next is msgKey encrypted with the folder Key, and the encrypted file data

		}else{														//single file mode: asymmetric encryption

			var recipients = new Uint8Array([locksSelected.length]),		//byte after header will be the number of recipients; array of length 1
				locksShuffle = locksSelected.slice();					//clone selected Locks array
			
			shuffle(locksShuffle);									//so encrypted keys are not always in the same order

			var	msgKey = nacl.randomBytes(32),	//message key for symmetric encryption
				nonce = nacl.randomBytes(24);	//nonce so each encryption is unique; 24 bytes

			fileOutBin = concatUi8([headTag,recipients,nonce,myLock.slice(0,8)]);	//global output starts with header v1, No. of recipients, 24-byte nonce, first 8 bytes of sender's public Key			
			
			if(isKeyFile){
				var cipher = new Uint8Array(0);										//empty payload for a Folder Key file
				if(folderKey) msgKey = folderKey									//if folder key is in memory, reuse it as message key
			}else{
				var cipher = nacl.secretbox(fileInBin,nonce,msgKey)						//main encryption event, but don't add the result yet
			}

			//for each public key, encrypt the message key and add it, prefaced by the first 8 bytes of the ciphertext obtained when the item is encrypted with the message nonce and the shared key. Notice: same nonce, but different key for each item (unless someone planted two recipients who have the same key, but then the encrypted result will also be identical).
			for (i = 0; i < locksShuffle.length; i++){
				var sharedKey = makeShared(locksShuffle[i],myKey),								//use encrypter's private key: signed mode
					cipher2 = nacl.secretbox(msgKey,nonce,sharedKey);						//message Key encrypted for each recipient

				var	idTag = nacl.secretbox(locksShuffle[i],nonce,sharedKey).slice(0,8);		//8 bytes of each public key, encrypted; this precedes each encrypted message Key

				fileOutBin = concatUi8([fileOutBin,idTag,cipher2]);
			}
			//all recipients done at this point; finish off by adding the encrypted message

			fileOutBin = concatUi8([fileOutBin,cipher]);
		}

		//finish with messages and saving encrypted file
		fileMsg.style.color = 'green';		
		if(isKeyFile){
			singleMode.checked = false;
			folderKey = msgKey;
			makeKeyBtn.textContent = 'Update Folder Key';
			fileMsg.textContent = 'Folder Key file created; You can now encrypt files under this key';
			step2.style.display = 'none';
			step3.style.display = 'block'
			saveFileOut(fileOutBin,'_FolderKey.crypt')	
		}else{		
			fileMsg.textContent = 'Encryption successful. File saved to Downloads';
			saveFileOut(fileOutBin,fileOutName)	
		}
	},20)
}

function decrypt(fileInBin, fileOutName){
	if(!fileInBin) return;
	if(!refreshKey()) return;			//check that the Key is active and stop if not
	if(locks.length <= 0) return;

	startBlink(false);
	
	setTimeout(function(){

		var isFolderMode = (fileInBin[headTag.length] == 0);			//zero recipients: folder mode, otherwise file by file mode

		if(isFolderMode){																//symmetric mode decryption
			if(!folderKey){
				fileMsg.style.color = 'red';
				fileMsg.textContent = 'To decrypt files encrypted in Folder mode, you must load an encrypted Folder Key first'
				return
			}

			var nonce = fileInBin.slice(headTag.length+1,headTag.length+25),			//24 bytes; there is a 0 byte right before it
				msgKeyCipher = fileInBin.slice(headTag.length+25,headTag.length+73),	//encrypted key, 48 bytes
				cipher = fileInBin.slice(headTag.length+73);							//rest of it; encrypted file

			var msgKey = nacl.secretbox.open(msgKeyCipher,nonce,folderKey);				//decrypt the message key
			if(!msgKey){
				fileMsg.style.color = 'red';
				fileMsg.textContent = 'Decryption has failed';
				fileOutBin = '';
				return
			}

			var fileOutBin = nacl.secretbox.open(cipher,nonce,msgKey);								//main file decryption

			if(!fileOutBin){												//decryption failed
				fileMsg.style.color = 'red';
				fileMsg.textContent = 'Decryption has failed'
			}else{
				fileMsg.style.color = 'green';								//success!
				fileMsg.textContent = 'Decryption successful. File saved to Downloads';
				saveFileOut(fileOutBin,fileOutName)							//download automatically if the Save button is not showing
			}

		}else{																		//asymmetric mode decryption
			var	recipients = fileInBin[headTag.length],								//number of recipients. '0' reserved for folder mode
				cipherArray = new Array(recipients),
				stuffForId = myLock;

			var nonce = fileInBin.slice(headTag.length+1,headTag.length+25),		//24 bytes
				lockID = fileInBin.slice(headTag.length+25,headTag.length+33),		//first 8 bytes of sender's public key
				cipherInput = fileInBin.slice(headTag.length+33);					//rest of it; contains IDtags + encrypted message keys, and encrypted file

			var index = lockIndex(lockID,locks,8);									//find whose public key was used to encrypt

			if(index == -1){														//not found
				fileMsg.style.color = 'red';
				fileMsg.textContent = 'File encrypted by unknown or unselected user';
				return
			}

			//cut the rest into pieces; first the ID tags with their encrypted keys, then the encrypted file	
			for(var i = 0; i < recipients; i++){
				cipherArray[i] = cipherInput.slice(56*i,56*(i+1))					//8 bytes for ID tag, 48 for encrypted key
			}
			var cipher = cipherInput.slice(56*recipients);							//file after symmetric encryption; key yet to be extracted

			var	sharedKey = makeShared(locks[index],myKey)
			
			var	idKey = sharedKey;

			var idTag = nacl.secretbox(stuffForId,nonce,idKey).slice(0,8);			//this will be found right before the message key encrypted for me
			
			//look for my ID tag and return the bytes that follow it
			for(i = 0; i < recipients; i++){
				var success = true;
				for(var j = 0; j < 8; j++){										//just the first 8 bytes
					success = success && (idTag[j] == cipherArray[i][j])		//find the idTag bytes at the start of cipherArray[i]
				}
				if(success){
					var msgKeyCipher = cipherArray[i].slice(8);
					break
				}
			}

			if(!success){														//ID tag not found; display error and bail out
				fileMsg.style.color = 'red';
				fileMsg.textContent = 'This file is not encrypted for you';
				return
			}

			var msgKey = nacl.secretbox.open(msgKeyCipher,nonce,sharedKey);		//decrypt the message key
			if(!msgKey){
				fileMsg.style.color = 'red';
				fileMsg.textContent = 'Decryption has failed';
				return
			}

			var sender = users[index].replace(/\$/,'former user ')

			if(cipher.length == 0){												//encrypted folder Key
				folderKey = msgKey;
				fileMsg.style.color = 'green';
				fileMsg.textContent = 'Folder Key loaded. You are now set to encrypt and decrypt files from this folder. Last updated by ' + sender;
				singleMode.checked = false;
				makeKeyBtn.textContent = 'Update Folder Key';
				fileImg.src = 'images/folder-white.png';
				fileLbl.title = "drop files to be encrypted of decrypted"
				step2.style.display = 'none';
				step3.style.display = 'block'

			}else{																//asymmetric-encrypted file
				var fileOutBin = nacl.secretbox.open(cipher,nonce,msgKey);						//decrypt the main message; false if error

				if(!fileOutBin){												//decryption failed
					fileMsg.style.color = 'red';
					fileMsg.textContent = 'Decryption has failed'
				}else{
					fileMsg.style.color = 'green';								//success!
					fileMsg.textContent = 'Decryption successful. File saved to Downloads. Last updated by ' + sender;
					saveFileOut(fileOutBin,fileOutName)							//download automatically if the Save button is not showing
				}
			}
		}

	},20)						//delay to allow blinker to start
}

//makes the DH public string of a DH secret key array. Returns a Uint8 array
function makePub(sec){
	return pub = nacl.box.keyPair.fromSecretKey(sec).publicKey
}

//Diffie-Hellman combination of a DH public key array and a DH secret key array. Returns Uint8Array
function makeShared(pub,sec){
	return nacl.box.before(pub,sec)
}

//just to shuffle randomly an array; no pretensions of crypto strength
function shuffle(a) {
    var j, x, i;
    for (i = a.length; i; i -= 1) {
        j = Math.floor(Math.random() * i);
        x = a[i - 1];
        a[i - 1] = a[j];
        a[j] = x
    }
	return a
}

//to concatenate a few Uint8Arrays fed as an array
function concatUi8(arrays) {
	var totalLength = 0;
	for(var i = 0; i < arrays.length; i++) totalLength += arrays[i].length;
	
	var result = new Uint8Array(totalLength);
  
	var length = 0;
	for(var i = 0; i < arrays.length; i++) {
	  result.set(arrays[i], length);
	  length += arrays[i].length;
	}
	return result
}

//to start the blinker during encryption or decryption
function startBlink(isEncrypt){
	fileMsg.textContent = '';
    var blinker = document.createElement('span');
    blinker.className = "blink";
    if(isEncrypt){blinker.textContent = "ENCRYPTING..."}else{blinker.textContent = "DECRYPTING..."};
    fileMsg.appendChild(blinker)
}

//to save the output file to Downloads
function saveFileOut(fileBin,name){
	if(fileBin) downloadBlob(fileBin, name, 'application/octet-stream')
}

//from StackOverflow, to download Uint8Array data as file. Usage: downloadBlob(myBinaryBlob, 'some-file.bin', 'application/octet-stream');
var downloadBlob, downloadURL;

downloadBlob = function(data, fileInName, mimeType) {
  var blob, url;
  blob = new Blob([data], {
    type: mimeType
  });
  url = window.URL.createObjectURL(blob);
  downloadURL(url, fileInName);
  setTimeout(function() {
    return window.URL.revokeObjectURL(url);
  }, 1000);
};

downloadURL = function(data, fileInName) {
  var a;
  a = document.createElement('a');
  a.href = data;
  a.download = fileInName;
  document.body.appendChild(a);
  a.style = 'display: none';
  a.click();
  a.remove();
};

var locks = [], users = [];						//locks contains public keys for all users in uint8 format, users contains the matching names
var locksSelected = [];							//only for selected users; excludes lecagy users

//recognize pure base36 and length is 50: ezLock
function isLock(string){
	return !string.match(/[^a-zL0-9]/) && (string.length == 50)				//allow both capital and smallcase L, in case of typing error
}

//grab the names in GroupKeys.js and put them in the selection box
function fillList(){
	var headingColor = '639789';
	groupList.textContent = '';
	var fragment = document.createDocumentFragment(),
		opt2 = document.createElement("option");
	opt2.disabled = true;
	opt2.selected = true;
	opt2.textContent = "Select users (ctrl-click for several)";
	fragment.appendChild(opt2);

	var usersSelected = [];
	for(var name in GroupKeys){
		if(name.charAt(0) != '$'){							//not a legacy user
			var opt = document.createElement("option");
			opt.value = name;
			opt.textContent = name;
			fragment.appendChild(opt);
			if(isLock(GroupKeys[name])){					//make array just with public keys in Uint8 format
				var lock64 = changeBase(GroupKeys[name].trim().replace(/l/g,'L'),base36,base64);		//make capital 'L' in case it was written in smallcase
				while (lock64.length < 43) lock64 = 'A' + lock64;										//prepend zeros to get correct length
				locks.push(nacl.util.decodeBase64(lock64));
				users.push(name);
				locksSelected.push(nacl.util.decodeBase64(lock64));
				usersSelected.push(name)
			}
		}else{												//legacy user: do not list, but add public key to locks array
			if(isLock(GroupKeys[name])){
				var lock64 = changeBase(GroupKeys[name].trim().replace(/l/g,'L'),base36,base64);		//make capital 'L' in case it was smallcase
				while (lock64.length < 43) lock64 = 'A' + lock64;										//prepend zeros to get correct length
				locks.push(nacl.util.decodeBase64(lock64));
				users.push(name)
			}
		}
	}
	groupList.style.color = '#' + headingColor;
	groupList.appendChild(fragment);
	groupList.options[0].selected = false;
	usersSelected = usersSelected.sort();							//alphabetical order
	userList.textContent = usersSelected.join(', ')
}

//deselect all entries on selection box
function deselectList(){
	for (var i = 1; i < groupList.options.length; i++) {
        groupList.options[i].selected = false
      }
}

//updates recipient lists from entries selected in the selection element
function updateUsers(){
	var list = [],
		usersSelected = [];				//reset selected users and locks lists
	locksSelected = [];

	//make first list of selected names, some of which may be lists
	for(var i = 1; i < groupList.options.length; i++){		//skip header entry
    	if(groupList.options[i].selected){
			list.push(groupList.options[i].value)
		}
	}

	if(list.length == 0){									//if no selection, add all single names
		for(var name in GroupKeys){
			if(name.charAt(0) != '$'){						//only active users
				if(isLock(GroupKeys[name])){
					usersSelected.push(name)
				}
			}
		}
	}else{
		//convert the entries that are themselves lists into individual names
		for(var i = 0; i < list.length; i++){
			if(isLock(GroupKeys[list[i]])){						//single member, add the name to users list
				usersSelected.push(list[i])	
			}else{
				usersSelected = usersSelected.concat(GroupKeys[list[i]].split(', '))		//list, so add all the names
			}
		}
		usersSelected = usersSelected.filter(onlyUnique);						//remove duplicates
	}

	for(var i = 0; i < usersSelected.length; i++){					//remove names that are not in database; length will change
		if(!GroupKeys[usersSelected[i]]) usersSelected.splice(i,1)
	}
	
	usersSelected = usersSelected.sort();									//alphabetize

	var lock64;
	for(var i = 0; i < usersSelected.length; i++){					//fill encrypt array
		if(usersSelected[i] != myName){								//active user to be added after, even if not selected
			lock64 = changeBase(GroupKeys[usersSelected[i]],base36,base64);
			while (lock64.length < 43) lock64 = 'A' + lock64;					//prepend zeros to get correct length
			locksSelected.push(nacl.util.decodeBase64(lock64))
		}
	}
	locksSelected.push(myLock)										//add active user to encrypt array

	userList.textContent = usersSelected.join(', ')
}

//to remove duplicates in an array
function onlyUnique(value, index, self) {
	return self.indexOf(value) === index;
}

//to sort an object alphabetically; for filling the list
function sortObject(obj) {
    return Object.keys(obj).sort().reduce(function (result, key) {
        result[key] = obj[key];
        return result;
    }, {});
}

//process data contained in GroupKeys.js
const groupName = GroupKeys['GroupName'];
const headTag = JSON.parse(GroupKeys['HeadTag']);
delete GroupKeys['GroupName'];
delete GroupKeys['HeadTag'];

GroupKeys = sortObject(GroupKeys);

//these require the DOM elements to be defined
document.addEventListener("DOMContentLoaded", () => {

    groupNameBox.textContent = groupName;			//rest of initialization
    fillList();

    acceptBtn.addEventListener('click', acceptPwd);
    showPwdMode.addEventListener('click', showPwd);
    adminBtn.addEventListener('click', function(){window.open('admin.html')});
	admin.addEventListener('click', function(){
		if(selectArea.style.display == ''){
            selectArea.style.display = 'block'
        }else{
            selectArea.style.display = '';
            deselectList();
            updateUsers();
			singleMode.checked = false;
			selectFileIcon()
        }
	});
	singleMode.addEventListener('click', function(){
		if(singleMode.checked){
			fileImg.src = 'images/folder-white.png';
			fileLbl.title = "drop files to be encrypted of decrypted in File by File mode"
		}else{
			selectFileIcon()
		}
	})
	function selectFileIcon(){
		if(folderKey){
			fileImg.src = 'images/folder-white.png';
			fileLbl.title = "drop files to be encrypted of decrypted"
		}else{
			fileImg.src = 'images/key-white.png';
			fileLbl.title = "drop a Folder Key here"
		}
	}
    pwdBox.addEventListener('keyup', pwdKeyup, false);
    groupList.addEventListener('change',updateUsers);
    makeKeyBtn.addEventListener('click',makeKeyFile);

//add files functionality to the drop area
	fileIn.addEventListener('change',loadFiles);
	fileLbl.addEventListener('mouseover',function(){fileLbl.classList.add('dropHover')});
	fileLbl.addEventListener('mouseout',function(){fileLbl.classList.remove('dropHover')});
	fileLbl.ondragover = function(evt) {
		evt.preventDefault();
		fileLbl.classList.add('dropReady');
		fileLbl.classList.remove('dropHover')
	};
	fileLbl.ondragenter = function(evt) {
		evt.preventDefault();
		fileLbl.classList.add('dropReady');
		fileLbl.classList.remove('dropHover')
	};
	fileLbl.ondragleave = function (evt) {
		evt.preventDefault();
		fileLbl.classList.remove('dropReady');
		fileLbl.classList.remove('dropHover')
	};
	fileLbl.ondrop = function(evt) {
		evt.preventDefault();
		fileLbl.classList.remove('dropReady');
		fileLbl.classList.remove('dropHover');

		fileIn.files = evt.dataTransfer.files;

		loadFiles(evt)
	};
})
