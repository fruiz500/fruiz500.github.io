<?php
//code for accepting javascript fetch request and filling the text area when the page loads is not needed. Regular HTML handles that through the fetch API

//code for updating the file after form submit. From w3schools

$pwd = $_POST["password"];

$acceptedHashes = array('##################', '******************');     //to be replaced by actual hashes from actual Administrator passwords

$isPasswordCorrect = 0;                                 //initialize check

for($i = 0; $i < count($acceptedHashes); $i++){
    $isPasswordCorrect += password_verify($pwd, $acceptedHashes[$i]);
    if($isPasswordCorrect) break;
};

if($isPasswordCorrect){
    $myfile = fopen("GroupKeys.js", "w") or die("Unable to open file!");
    $txt = $_POST["code"];                          //submitted by front end
    fwrite($myfile, $txt);
    fclose($myfile);
    echo "Update Successful. Go back and reload to check";
}else{
    $hash = password_hash($pwd, PASSWORD_DEFAULT);          //this contains a salt as well
    echo "Password not recognized. This is its hash: " . $hash;
};
?>
