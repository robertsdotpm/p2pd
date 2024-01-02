<?php

/*
This file creates an API for a simple key-value store.

A key-value store simply lets you store data by a name. Just like variables
in programming or 'dictionaries' / associative arrays / hash tables.
For this key-value store 'ownership' of names is enforced by using
ECDSA signatures. API calls must therefore be signed. Names DO eventually
expire to prevent abuse.

The purpose of this script is to provide the means to build a simple
DNS-like service on top of it for which peers can use fixed names for
connections without worrying about exchanging addresses via an 'out of band'
channel. This is provided to simplify the use of the library for demos and
such. Production software should eventually use their own services.

Requirements:

(1) The script uses SQLite for its DB and Libsodium to do crypto.
(2) The corresponding client for this has been written in Python.
*/

// Config <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$digest = "SHA512";
$curve = "ed22519";
$oid = "1.3.132.0.10";
$prune_interval = 2592000; // A month in seconds.
$db_path = "kvs.db";

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

// Errors <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

$KVS_ERRORS = array(
    "name not registered"
);

function kvs_error($offset)
{
    global $KVS_ERRORS;
    return 'KVS_ERROR = "' . $KVS_ERRORS[$offset] . '"'; 
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

// Utility <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

// Used to convert pub key XY to dec str.
function hex_str_to_dec_str($hex)
{
    $dec = 0;
    $len = strlen($hex);
    for ($i = 1; $i <= $len; $i++) {
        $dec = bcadd(
            $dec,
            bcmul(strval(hexdec($hex[$i - 1])),
            bcpow('16', strval($len - $i)))
        );
    }
    return $dec;
}

function is_hex($v)
{
    return preg_match('/^[0-9a-f]+$/i', $v);
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//var_dump($key_pair); die();
//var_dump(bin2hex($priv_key));
//var_dump(bin2hex($pub_key));
//var_dump($is_valid_sig);

//var_dump($sig);
//var_dump($key_pair);

class MyDB extends SQLite3
{
    function __construct()
    {
        global $db_path;
        $this->open($db_path);
    }
}

function does_name_exist($db, $name)
{
    // Setup safe input params.
    $sql = $db->prepare('SELECT * FROM `names` WHERE `name`=:name');
    $sql->bindValue(':name', $name, SQLITE3_TEXT);
    
    // Execute query.
    $result = $sql->execute();
    return $result->fetchArray();
}

//                    hex
function kv_add($db, $pub_key, $name, $value)
{
    // Setup safe input params.
    $sql = $db->prepare("INSERT INTO names (pub_key, name, value, timestamp) VALUES (:pub_key, :name, :value, :timestamp)");
    $sql->bindValue(':pub_key', $pub_key, SQLITE3_TEXT);
    $sql->bindValue(':name', $name, SQLITE3_TEXT);
    $sql->bindValue(':value', $value, SQLITE3_TEXT);
    $sql->bindValue(':timestamp', time(), SQLITE3_INTEGER);
    
    // Execute query.
    $result = $sql->execute();
    //var_dump($result->fetchArray());
}

function api_pre_img($nonce, $name, $value)
{
    return strval($nonce) . $name . $value;
}

//                                hex                     hex
function kv_validate($db, $row, $pub_key, $name, $value, $sig)
{
    // Check if sig is valid.
    $msg  = api_pre_img($row['nonce'], $name, $value);
    $pub_key = hex2bin($row['pub_key']);
    $sig = hex2bin($sig);
    $is_valid_sig = sodium_crypto_sign_verify_detached($sig, $msg, $pub_key);
    if(!$is_valid_sig)
    {
        return false;
    }
    
    // Update the none and value.
    $sql = $db->prepare("UPDATE names SET value = :value, nonce = :nonce, timestamp = :timestamp WHERE name == :name");
    $sql->bindValue(':name', $name, SQLITE3_TEXT);
    $sql->bindValue(':value', $value, SQLITE3_TEXT);
    $sql->bindValue(':timestamp', time(), SQLITE3_INTEGER);
    
    // Increment nonce to prevent replay attacks.
    $sql->bindValue(':nonce', $row['nonce'] + 1, SQLITE3_INTEGER);
    
    // Execute query.
    $result = $sql->execute();
    return true;
}

// Delete entries older than a threshold.
function kv_prune($db)
{
    global $prune_interval;
    $cur_time = time();
    
    $sql = $db->prepare("DELETE FROM names WHERE timestamp + :secs <= :cur_time");
    $sql->bindValue(':secs', $prune_interval, SQLITE3_INTEGER);
    $sql->bindValue(':cur_time', $cur_time, SQLITE3_INTEGER);
    $result = $sql->execute();
}

function get_nonce($db, $name)
{
    $row = does_name_exist($db, $name);
    if(!$row) return 0;
    
    return $row['nonce'];
}

// Load SQLLite DB.
$db = new MyDB();

// Delete all expired rows.
kv_prune($db);

// API <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

$action = $_GET['action'] ?? '';
$name = $_GET['name'] ?? '';
$value = $_GET['value'] ?? '';
$nonce = $_GET['nonce'] ?? '';
$pub_key = $_GET['pub_key'] ?? '';
$sig = $_GET['sig'] ?? '';

// No name provided.
if(!strlen($name)) die('0');

// Get row that belongs to name.
$row = does_name_exist($db, $name);

// API methods.
switch($action)
{
    // Nonce needs to be included with set_val.
    case 'get_nonce':
        // Name not registered.
        if(!$row) die("0");
        
        // Return just the nonce portion.
        die(strval($row['nonce']));
        break;
        
    // Get a value at a name.
    case 'get_val':
        // Name not registered.
        if(!$row) die(kvs_error(0));
        
        // Return the value.
        die($row['value']);
        break;
        
    // Create or update a value.
    case 'set_val':
        // Pub key 64 bytes.
        if(strlen($pub_key) != 64)
        {
            die('pub key must be 64 bytes');
        }
        
        // Pub key hex.
        if(!is_hex($pub_key))
        {
            die('pub key must be hex');
        }
        
        // Sig 128 bytes.
        if(strlen($sig) != 128)
        {
            die('sig must be 128 bytes');
        }
        
        // Sig hex.
        if(!is_hex($sig))
        {
            die('sig must be hex');
        }
        
        // Nonce must be numeric.
        if(!is_numeric($nonce))
        {
            die('nonce must be numeric');
        }
        
        // Value must be provided.
        if(!strlen($value))
        {
            die('no value provided');
        }

        // If there is no row then make it.
        if(!$row)
        {
            kv_add($db, $pub_key, $name, $value);
            $row = does_name_exist($db, $name);
        }        
        
        // Success.
        $out = kv_validate($db, $row, $pub_key, $name, $value, $sig);
        if($out) die('1');
        
        // Failure.
        die('sig validation failed');
        break;
        
    default:
        die();
        break;
}


/*
$key_pair = sodium_crypto_sign_keypair();
$priv_key = sodium_crypto_sign_secretkey($key_pair); // 32 (seed), 32 ($pub_key)


//The public key is encoded as compressed EC point: the y-coordinate,
//combined with the lowest bit (the parity) of the x-coordinate
$pub_key = sodium_crypto_sign_publickey($key_pair); // 32: (y & x)

$name = 'test name 14';
$value = 'test val';
$nonce = 1;
$msg = strval($nonce) . $name . $value;
$sig = sodium_crypto_sign_detached($msg, $priv_key); // 64 (R, s) 32 (sig point, sig scalar)
$is_valid_sig = sodium_crypto_sign_verify_detached($sig, $msg, $pub_key);
*/


//kv_prune($db);

//$r = kv_validate($db, bin2hex($pub_key), $name, $value, bin2hex($sig));
//echo($r);

?>